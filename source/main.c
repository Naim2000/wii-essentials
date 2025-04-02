#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/endian.h>
#include <errno.h>
#include <ogc/machine/processor.h>
#include <ogc/isfs.h>
#include <network.h>
#include <fat.h>

#include "common.h"
#include "pad.h"
#include "video.h"
#include "libpatcher/libpatcher.h"
#include "es_structs.h"
#include "exefs.h"
#include "sha256.h"

#define HW_AHBPROT		0x0D800064
#define HW_OTPCOMMAND	0x0D8001EC
#define HW_OTPDATA		0x0D8001F0

typedef union {
	struct {
		uint32_t boot1_hash[5];
		uint32_t common_key[4];
		uint32_t device_id;
		union {
			uint8_t device_private_key[30];
			struct {
				uint32_t pad[7];
				uint32_t nandfs_hmac_key[5];
			};
		};
		uint32_t nandfs_key[4];
		uint32_t backup_key[4];
		uint32_t pad2[2];
	};
	uint32_t data[0x20];
} WiiOTP;
CHECK_STRUCT_SIZE(WiiOTP, 0x80);

int otp_read(unsigned offset, unsigned count, uint32_t out[count]) {
	if (offset + count > 0x20 || !out)
		return 0;

	for (unsigned i = 0; i < count; i++) {
		write32(HW_OTPCOMMAND, 0x80000000 | (offset + i));
		out[i] = read32(HW_OTPDATA);
	}

	return count;
}

struct nandfile {
	const char  name[8];
	const char *path;
	void       *data;
	unsigned    size;
};

int nand_read_simple(struct nandfile* p) {
	int       ret, fd = -1;
	uint32_t  fstats[2];

	ret = fd = ISFS_Open(p->path, 1);
	if (ret < 0) {
		print_error("ISFS_Open(%s)", ret, p->path);
		return ret;
	}

	ret = IOS_Ioctl(fd, 11, NULL, 0, fstats, sizeof fstats);
	if (ret < 0) {
		print_error("FS GetFileStats(%s)", ret, p->path);
		ISFS_Close(fd);
		return ret;
	}

	p->size = *fstats;
	p->data = memalign32(p->size);
	if (!p->data) {
		print_error("memory allocation", 0);
		ISFS_Close(fd);
		return -1;
	}

	ret = ISFS_Read(fd, p->data, p->size);
	ISFS_Close(fd);
	if (ret != p->size) {
		free(p->data);
		p->data = NULL;
		ret = IOS_Ioctl(fd, 11, NULL, 0, fstats, sizeof fstats);
	}

	return ret;
}

void CryptSettingTxt(const char* in, char* out)
{
	uint32_t key = 0x73B5DBFA;

	for (int i = 0; i < 0x100; i++) {
		out[i] = in[i] ^ key;
		key = (key << 1) | (key >> 31);
	}
}

int GetSettingValue(int len; const char* setting, const char* item, char out[len], int len) {
	const char* ptr = setting;

	while (ptr - setting < 0x100) {
		const char* value = strchr(ptr, '=');
		const char* endptr = strchr(ptr, '\r') ?: strchr(ptr, '\n');

		if (!value || !endptr)
			break;

		int nlen = value++ - ptr;
		int vlen = endptr - value;

		if (nlen == strlen(item) && memcmp(ptr, item, nlen) == 0) {
			if (vlen >= len) {
				printf("Item %s is too large (=%.*s)\n", item, vlen, value);
				return 0;
			}

			memcpy(out, value, vlen);
			out[vlen] = '\0';
			return vlen;
		}

		while (isspace((int)*++endptr))
			;

		ptr = endptr;
	}

	printf("Could not find item %s\n", item);
	return 0;
}

// bonus
// thank you WiiLink Mail Patcher
enum
{
	URL_COUNT = 0x05,
	MAX_URL_LENGTH = 0x80,
	MAX_EMAIL_LENGTH = 0x40,
	MAX_PASSWORD_LENGTH = 0x20,
	MAX_MLCHKID_LENGTH = 0x24,
};

typedef struct
{
	uint32_t magic;    // 'WcCf' 0x57634366
	uint32_t version;  // must be 8
	int64_t  nwc24_id;
	uint32_t id_generation;
	uint32_t creation_stage;
	char     email[MAX_EMAIL_LENGTH];
	char     paswd[MAX_PASSWORD_LENGTH];
	char     mlchkid[MAX_MLCHKID_LENGTH];
	char     http_urls[URL_COUNT][MAX_URL_LENGTH];
	char     reserved[0xDC];
	uint32_t enable_booting;
	uint32_t checksum;
} NWC24Msg;

#define BACKUP_DIR "/private/wii/backups"
int do_backup() {
	int       ret;
	char      outpath[160];
	uint32_t  device_id;

	ret = ES_GetDeviceID(&device_id);
	if (ret < 0) {
		print_error("ES_GetDeviceID", ret);
		return ret;
	}

	printf("Device ID: %08x (%u)\n", device_id, device_id);
	if (device_id == 0x0403AC68) {
		printf("Hello dolphin-emu...\n");
		// return -1;
	}

	// printf("Saving backup files to " BACKUP_DIR "\n", device_id);

	sprintf(outpath, BACKUP_DIR "/");
	for (char* ptr = outpath; (ptr = strchr(ptr, '/')) != NULL; ptr++)
	{
		*ptr = 0;
		ret = mkdir(outpath, 0644);
		*ptr = '/';

		if (ret < 0 && errno != EEXIST) {
			perror(outpath);
			return -errno;
		}
	}

	WiiOTP otp = {};
	otp_read(0, 0x20, otp.data);

	DeviceCert device_cert = {};
	ret = ES_GetDeviceCert((void *)&device_cert);
	if (ret < 0) {
		print_error("ES_GetDeviceCert", ret);
		return ret;
	}

	ExeFSHeader header = {};
	struct nandfile nandfiles[5] = {
		{ "setting",	"/title/00000001/00000002/data/setting.txt" },
		{ "ec",			"/title/00010002/48414241/data/ec.cfg" },
		{ "sysconf",	"/shared2/sys/SYSCONF" },
		{ "authdata",	"/shared2/DWC_AUTHDATA" },
		{ "nwc24msg",	"/shared2/wc24/nwc24msg.cfg" },
	};

	int i;
	for (i = 0; i < 5; i++) {
		struct nandfile* p = &nandfiles[i];

		ret = nand_read_simple(p);
		if (ret < 0)
			goto cleanup_files;

		memcpy(header.files[i].name, p->name, 8);
		header.files[i].size = htole32(p->size);
		header.files[i].offset = htole32(i ? le32toh(header.files[i - 1].offset) + align_up(le32toh(header.files[i - 1].size), EXEFS_BLOCK_SIZE) : 0);
		sha256(p->data, p->size, (uint8_t *)header.hashes[EXEFS_NUM_FILES + ~i]);
	}

	strncpy(header.files[i].name, "devcert", 8);
	header.files[i].size = htole32(sizeof device_cert);
	header.files[i].offset = htole32(le32toh(header.files[i - 1].offset) + align_up(le32toh(header.files[i - 1].size), EXEFS_BLOCK_SIZE));
	sha256((uint8_t *)&device_cert, sizeof device_cert, (uint8_t *)header.hashes[EXEFS_NUM_FILES + ~i]);
	i++;

	strncpy(header.files[i].name, "otp", 8);
	header.files[i].size = htole32(sizeof otp);
	header.files[i].offset = htole32(le32toh(header.files[i - 1].offset) + align_up(le32toh(header.files[i - 1].size), EXEFS_BLOCK_SIZE));
	sha256((uint8_t *)otp.data, sizeof otp, (uint8_t *)header.hashes[EXEFS_NUM_FILES + ~i]);
	i++;

	uint32_t exefs_size = CalculateExeFSSize(&header);
	if (!exefs_size) {
		print_error("CalculateExeFSSize", 0);
		goto cleanup_files;
	}

	ExeFS exefs = malloc(exefs_size);
	if (!exefs) {
		print_error("memory allocation", 0);
		goto cleanup_files;
	}

	exefs->header = header;

	for (i = 0; i < 5; i++)
		memcpy(exefs->data + le32toh(exefs->header.files[i].offset), nandfiles[i].data, nandfiles[i].size);

	memcpy(exefs->data + le32toh(exefs->header.files[i++].offset), &device_cert, sizeof device_cert);
	memcpy(exefs->data + le32toh(exefs->header.files[i++].offset), otp.data, sizeof otp);

	// GodMode9 reference !!!
	char serial[16] = {};
	{
		char settingbuf[0x100] = {};

		CryptSettingTxt(nandfiles[0].data, settingbuf);
		ret = GetSettingValue(settingbuf, "CODE", serial, 4);
		if (!ret || !GetSettingValue(settingbuf, "SERNO", serial + ret, sizeof serial - ret)) {
			puts("Unable to determine serial number!");
			sprintf(serial, "NG%08x", device_id);
		} else {
			printf("Serial number: %s\n", serial);
		}
	}
	// bonus
	NWC24Msg* msg = (NWC24Msg *)nandfiles[4].data;
	printf("Wii number: %016lli\n", msg->nwc24_id);

	// puts("Writing essential.exefs...");
	for (int x = 0; x < 100; x++) {
		struct stat st;

		sprintf(outpath, BACKUP_DIR "/%s_essential_%02d.exefs", serial, x);
		if (stat(outpath, &st) < 0)
			break;

		if (st.st_size == exefs_size) {
			uint8_t hashes[2][SHA256_BLOCK_SIZE] = {};
			sha256((uint8_t *)exefs,  exefs_size, hashes[0]); // *

			ExeFS exefs2 = malloc(exefs_size);
			if (!exefs) {
				print_error("memory allocation*", 0);
				break;
			}

			FILE* fpr = fopen(outpath, "rb");
			if (!fpr)
				break;

			ret = fread(exefs2, exefs_size, 1, fpr);
			fclose(fpr);

			if (ret)
				sha256((uint8_t *)exefs2, exefs_size, hashes[1]);

			free(exefs2);
			if (memcmp(hashes[0], hashes[1], SHA256_BLOCK_SIZE) == 0) {
				printf("No changes since %s.\n", outpath);
				goto cleanup_files;
			}
		}
	}
	printf("Writing %s ...\n", outpath);
	FILE* fp = fopen(outpath, "wb");
	if (!fp) {
		perror(outpath);
	} else {
		if (!fwrite(exefs, exefs_size, 1, fp))
			perror(outpath);

		fclose(fp);
	}
	free(exefs);

cleanup_files:
	for (int i = 0; i < 5; i++)
		free(nandfiles[i].data);

	if (otp.device_id == device_id) {
		puts("Printing keys...");
		sprintf(outpath, BACKUP_DIR "/%s_keys.txt", serial);
		fp = fopen(outpath, "w");
		if (!fp) {
			perror(outpath);
			return -errno;
		}

		fprintf(fp, "BOOT1_HASH=%08x%08x%08x%08x%08x\n", otp.boot1_hash[0], otp.boot1_hash[1], otp.boot1_hash[2], otp.boot1_hash[3], otp.boot1_hash[4]);
		fprintf(fp, "COMMON_KEY=%08x%08x%08x%08x\n", otp.common_key[0], otp.common_key[1], otp.common_key[2], otp.common_key[3]);
		fprintf(fp, "DEVICE_ID=%08x\n", otp.device_id);

		char private_key_str[60];
		for (int i = 0; i < sizeof otp.device_private_key; i += 5)
			snprintf(private_key_str + i, sizeof private_key_str - i, "%02x%02x%02x%02x%02x",
					 otp.device_private_key[i+0], otp.device_private_key[i+1], otp.device_private_key[i+2], otp.device_private_key[i+3], otp.device_private_key[i+4]);

		fprintf(fp, "DEVICE_PRIVATE_KEY=%.60s\n", private_key_str);
		fprintf(fp, "NANDFS_KEY=%08x%08x%08x%08x\n", otp.nandfs_key[0], otp.nandfs_key[1], otp.nandfs_key[2], otp.nandfs_key[3]);
		fprintf(fp, "NANDFS_HMAC_KEY=%08x%08x%08x%08x%08x\n", otp.nandfs_hmac_key[0], otp.nandfs_hmac_key[1], otp.nandfs_hmac_key[2], otp.nandfs_hmac_key[3], otp.nandfs_hmac_key[4]);
		fprintf(fp, "BACKUP_KEY=%08x%08x%08x%08x\n", otp.backup_key[0], otp.backup_key[1], otp.backup_key[2], otp.backup_key[3]);

		fprintf(fp, "SERIAL=%s\n", serial);

		// bonus
		unsigned char mac[6] = {};
		net_get_mac_address(mac);
		fprintf(fp, "MAC_ADDRESS=%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		fflush(fp);
		fclose(fp);
	}


	return ret;
}

int main(int argc, char **argv) {
	printf("Hello World!\n");

	if (!apply_patches()) {
		print_error("apply_patches", false);
		sleep(5);
		return -1;
	}

	ISFS_Initialize();
	if (!fatInitDefault()) {
		fprintf(stderr, "fatInitDefault() failed. Nothing much to do here anymore.\n");
		goto exit;
	}

	do_backup();

exit:
	puts("Press any button to exit.");
	initpads();
	wait_button(0);
	return 0;
}
