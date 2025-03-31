#include <stdio.h>
#include <stdint.h>
#include <string.h>
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

struct file { void* data; unsigned size; };

int nand_read_simple(const char* path, struct file* out) {
	int       ret, fd = -1;
	uint32_t  fstats[2];

	ret = fd = ISFS_Open(path, 1);
	if (ret < 0) {
		print_error("ISFS_Open(%s)", ret, path);
		return ret;
	}

	ret = IOS_Ioctl(fd, 11, NULL, 0, fstats, sizeof fstats);
	if (ret < 0) {
		print_error("FS GetFileStats(%s)", ret, path);
		ISFS_Close(fd);
		return ret;
	}

	out->size = *fstats;
	out->data = memalign32(out->size);
	if (!out->data) {
		print_error("memory allocation", 0);
		ISFS_Close(fd);
		return -1;
	}

	ret = ISFS_Read(fd, out->data, out->size);
	ISFS_Close(fd);
	if (ret != out->size) {
		free(out->data);
		out->data = NULL;
		ret = IOS_Ioctl(fd, 11, NULL, 0, fstats, sizeof fstats);
	}

	return ret;
}

#define BACKUP_DIR "/private/wii/backups/NG%08x"
int do_backup() {
	int       ret;
	char      outpath[160];
	uint32_t  device_id;

	ret = ES_GetDeviceID(&device_id);
	if (ret < 0) {
		print_error("ES_GetDeviceID", ret);
		return ret;
	}

	printf("Device ID: %08x\n", device_id);
	if (device_id == 0x0403AC68) {
		printf("Hello dolphin-emu...\n");
		// return -1;
	}

	printf("Saving backup files to " BACKUP_DIR "\n", device_id);

	sprintf(outpath, BACKUP_DIR "/", device_id);
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

	struct nandfile {
		const char  name[8];
		const char *path;
		struct file file;
	} nandfiles[5] = {
		{ "setting",	"/title/00000001/00000002/data/setting.txt"},
		{ "ec",			"/title/00010002/48414241/data/ec.cfg"},
		{ "sysconf",	"/shared2/sys/SYSCONF"},
		{ "authdata",	"/shared2/DWC_AUTHDATA"},
		{ "nwc24msg",	"/shared2/wc24/nwc24msg.cfg"},
	};

	for (int i = 0; i < 5; i++) {
		struct nandfile* p = &nandfiles[i];
		ret = nand_read_simple(p->path, &p->file);
		if (ret < 0)
			goto cleanup_files;
	}

	///
	ExeFSHeader header = {};

	int i;
	for (i = 0; i < 5; i++) {
		struct nandfile* p = &nandfiles[i];

		strncpy(header.files[i].name, p->name, 8);
		header.files[i].size = htole32(p->file.size);
		header.files[i].offset = htole32(i ? le32toh(header.files[i - 1].offset) + align_up(le32toh(header.files[i - 1].size), EXEFS_BLOCK_SIZE) : 0);
		sha256(p->file.data, p->file.size, (uint8_t *)header.hashes[EXEFS_NUM_FILES + ~i]);
	}

	strncpy(header.files[i].name, "devcert", 8);
	header.files[i].size = htole32(sizeof device_cert);
	header.files[i].offset = htole32(le32toh(header.files[i - 1].offset) + align_up(le32toh(header.files[i - 1].size), EXEFS_BLOCK_SIZE));
	sha256((void *)&device_cert, sizeof device_cert, (uint8_t *)header.hashes[EXEFS_NUM_FILES + ~i]);
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
		memcpy(exefs->data + le32toh(exefs->header.files[i].offset), nandfiles[i].file.data, nandfiles[i].file.size);

	memcpy(exefs->data + le32toh(exefs->header.files[i++].offset), &device_cert, sizeof device_cert);
	memcpy(exefs->data + le32toh(exefs->header.files[i++].offset), otp.data, sizeof otp);

	puts("Writing essential.exefs...");
	sprintf(outpath, BACKUP_DIR "/essential.exefs", device_id);
	FILE* fp = fopen(outpath, "wb");
	if (!fp) {
		perror(outpath);
	} else {
		fwrite(exefs, exefs_size, 1, fp);
		fclose(fp);
	}

cleanup_files:
	for (int i = 0; i < 5; i++) {
		free(nandfiles[i].file.data);
	}
	///

	puts("Printing keys...");
	sprintf(outpath, BACKUP_DIR "/keys.txt", device_id);
	fp = fopen(outpath, "w");
	if (!fp) {
		perror(outpath);
		return -errno;
	}

	fprintf(fp, "BOOT1_HASH=%08x%08x%08x%08x%08x\n", otp.boot1_hash[0], otp.boot1_hash[1], otp.boot1_hash[2], otp.boot1_hash[3], otp.boot1_hash[4]);
	fprintf(fp, "COMMON_KEY=%08x%08x%08x%08x\n", otp.common_key[0], otp.common_key[1], otp.common_key[2], otp.common_key[3]);
	fprintf(fp, "DEVICE_ID=%08x\n", otp.device_id);

	char private_key_str[60 + 1];
	for (int i = 0; i < sizeof otp.device_private_key; i += 3)
		sprintf(private_key_str + i, "%02x%02x%02x", otp.device_private_key[i+0], otp.device_private_key[i+1], otp.device_private_key[i+2]);

	fprintf(fp, "DEVICE_PRIVATE_KEY=%.60s\n", private_key_str);
	fprintf(fp, "NANDFS_KEY=%08x%08x%08x%08x\n", otp.nandfs_key[0], otp.nandfs_key[1], otp.nandfs_key[2], otp.nandfs_key[3]);
	fprintf(fp, "NANDFS_HMAC_KEY=%08x%08x%08x%08x%08x\n", otp.nandfs_hmac_key[0], otp.nandfs_hmac_key[1], otp.nandfs_hmac_key[2], otp.nandfs_hmac_key[3], otp.nandfs_hmac_key[4]);
	fprintf(fp, "BACKUP_KEY=%08x%08x%08x%08x\n", otp.backup_key[0], otp.backup_key[1], otp.backup_key[2], otp.backup_key[3]);

	// bonus
	unsigned char mac[6];
	net_get_mac_address(mac);
	fprintf(fp, "MAC_ADDRESS=%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	fflush(fp);
	fclose(fp);

	return ret;
}

int main(int argc, char **argv) {
	printf("Hello World!\n");

	if (!apply_patches()) {
		print_error("apply_patches", false);
		sleep(5);
		return -1;
	}

	initpads();
	ISFS_Initialize();
	if (!fatInitDefault()) {
		fprintf(stderr, "fatInitDefault() failed. Nothing much to do here anymore.\n");
		return -1;
	};

	do_backup();

	puts("Press any button to exit.");
	wait_button(0);
	return 0;
}
