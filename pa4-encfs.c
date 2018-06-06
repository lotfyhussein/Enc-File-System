

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
#define ENC 1
#define DEC 0
#define Pass (-1)

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <assert.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include "aes-crypt.h"
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif



char* root_path;
char* key;


int is_encrypted(const char *path)
{
	int ret;
	char xattr_val[5];
	getxattr(path, "user.encfs", xattr_val, sizeof(char)*5);
	fprintf(stderr, "xattr set to: %s\n", xattr_val);

	ret = (strcmp(xattr_val, "true") == 0);
	return ret;
}


int add_encrypted_attr(const char *path)
{
	int ret;
	int setxattr_ret;
	setxattr_ret = setxattr(path, "user.encfs", "true", (sizeof(char)*5), 0);
	ret = setxattr_ret == 0;
	fprintf(stderr, "\nsetxattr %s\n", ret > 0 ? "success" : "failure");
	return ret;
}

char *rd_path(const char *path)
{
	size_t len = strlen(path) + strlen(root_path) + 1;
	char *root_dir = malloc(len * sizeof(char));

	strcpy(root_dir, root_path);
	strcat(root_dir, path);

	printf("%s\n", root_dir);

	return root_dir;
}

static int xmp_getattr(const char *fuse_path, struct stat *stbuf)
{
	char *path = rd_path(fuse_path);

	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *fuse_path, int mask)
{
	char *path = rd_path(fuse_path);

	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *fuse_path, char *buf, size_t size)
{
	char *path = rd_path(fuse_path);

	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int xmp_readdir(const char *fuse_path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	char *path = rd_path(fuse_path);

	DIR *dp;
	struct dirent *de;
	fprintf(stderr, "Path: %s\n", path);

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *fuse_path, mode_t mode, dev_t rdev)
{
	char *path = rd_path(fuse_path);

	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *fuse_path, mode_t mode)
{
	char *path = rd_path(fuse_path);

	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *fuse_path)
{
	char *path = rd_path(fuse_path);

	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *fuse_path)
{
	char *path = rd_path(fuse_path);

	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *fuse_path, mode_t mode)
{
	char *path = rd_path(fuse_path);

	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *fuse_path, uid_t uid, gid_t gid)
{
	char *path = rd_path(fuse_path);

	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *fuse_path, off_t size)
{
	char *path = rd_path(fuse_path);

	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *fuse_path, const struct timespec ts[2])
{
	char *path = rd_path(fuse_path);

	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(path, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *fuse_path, struct fuse_file_info *fi)
{
	char *path = rd_path(fuse_path);
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static inline int file_size(FILE *file) {
    struct stat st;

    if (fstat(fileno(file), &st) == 0)
        return st.st_size;

    return -1;
}

static int xmp_read(const char *fuse_path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	FILE *path_ptr, *tmpf;
	char *path;
	int res, action;

	path = rd_path(fuse_path);
	path_ptr = fopen(path, "r");
	tmpf = tmpfile();

	/* Either encrypt, or just move along. */
	action = is_encrypted(path) ? DEC : Pass;
	if (do_crypt(path_ptr, tmpf, action, key) == 0)
		return -errno;

	/* Something went terribly wrong if this is the case. */
	if (path_ptr == NULL || tmpf == NULL)
		return -errno;

	fflush(tmpf);
	fseek(tmpf, offset, SEEK_SET);


	res = fread(buf, 1, file_size(tmpf), tmpf);
	if (res == -1)
		res = -errno;

	fclose(tmpf);
	fclose(path_ptr);

	return res;
}

/* read_file: for debugging tempfiles */
int read_file(FILE *file)
{
	int c;
	int file_contains_something = 0;
	FILE *read = file; /* don't move original file pointer */
	if (read) {
		while ((c = getc(read)) != EOF) {
			file_contains_something = 1;
			putc(c, stderr);
		}
	}
	if (!file_contains_something)
		fprintf(stderr, "file was empty\n");
	rewind(file);
	/* fseek(tmpf, offset, SEEK_END); */
	return 0;
}

static int xmp_write(const char *fuse_path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	FILE *path_ptr, *tmpf;
	char *path;
	int res, action;
	int tmpf_descriptor;

	path = rd_path(fuse_path);
	path_ptr = fopen(path, "r+");
	tmpf = tmpfile();
	tmpf_descriptor = fileno(tmpf);



	if (path_ptr == NULL || tmpf == NULL)
		return -errno;


	if (xmp_access(fuse_path, R_OK) == 0 && file_size(path_ptr) > 0) {
		action = is_encrypted(path) ? DEC : Pass;
		if (do_crypt(path_ptr, tmpf, action, key) == 0)
			return --errno;

		rewind(path_ptr);
		rewind(tmpf);
	}


	res = pwrite(tmpf_descriptor, buf, size, offset);
	if (res == -1)
		res = -errno;


	action = is_encrypted(path) ? ENC : Pass;

	if (do_crypt(tmpf, path_ptr, action, key) == 0)
		return -errno;

	fclose(tmpf);
	fclose(path_ptr);

	return res;
}

static int xmp_statfs(const char *fuse_path, struct statvfs *stbuf)
{
	char *path = rd_path(fuse_path);

	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* fuse_path, mode_t mode,
		      struct fuse_file_info* fi)
{
	char *path = rd_path(fuse_path);

	(void) fi;

	int res;
	res = creat(path, mode);

	if(res == -1) {
		fprintf(stderr, "xmp_create: failed to creat\n");
		return -errno;
	}

	close(res);

	if (!add_encrypted_attr(path)){
		fprintf(stderr, "xmp_create: failed to add xattr.\n");
		return -errno;
	}

	return 0;
}


static int xmp_release(const char *fuse_path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */
	char *path = rd_path(fuse_path);

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *fuse_path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */
	char *path = rd_path(fuse_path);

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *fuse_path, const char *name,
			const char *value, size_t size, int flags)
{
	char *path = rd_path(fuse_path);

	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *fuse_path, const char *name, char *value,
			size_t size)
{
	char *path = rd_path(fuse_path);

	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *fuse_path, char *list, size_t size)
{
	char *path = rd_path(fuse_path);

	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *fuse_path, const char *name)
{
	char *path = rd_path(fuse_path);

	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {

	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create		= xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);

	if ((root_path = realpath(argv[argc - 4], NULL)) == NULL){
		fprintf(stderr, "Invalid root directory name.\n");
		return EXIT_FAILURE;
	}

	if ((key = argv[argc - 1]) == NULL){
		fprintf(stderr, "Please enter an encryption key.\n");
		return EXIT_FAILURE;
	}



	argv[argc-4] = argv[argc-3];
	argv[argc-1] = NULL;
	argc -= 3;

	return fuse_main(argc, argv, &xmp_oper, NULL);
}
