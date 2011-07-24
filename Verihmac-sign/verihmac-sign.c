#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include <openssl/hmac.h>

#define FBUFLEN 256
#define MD_SIZE 20
#define VERI_ATTR "security.verihmac"


#define SUCCESS 0
#define FAIL    1


char * key;
int verbose,num_signed;

int get_digest(const char * filename,unsigned char* buffer);
int ftw_function (const char *fpath, const struct stat *sb, int typeflag);
void print_help();

int main(int argc,char** argv)
{
  char *path; 
  int c,rflag; 
  char buffer[MD_SIZE];
  struct stat _stat;
  
  
  
  memset(buffer,0,MD_SIZE);
  
  verbose =0;
  num_signed=0;
  
  while ((c = getopt (argc, argv, "Rv")) != -1)
  {
      switch(c) 
      { 
	case 'R':
	  rflag=1;
	  break;
	case 'v':
	  verbose = 1;
	  break;
	  
	default:
	  print_help();
      } 
  }
  
  
  if(argc - optind != 2)
  { 
    print_help();    
  }
    
  path=argv[optind];
  key=argv[optind+1];

  
 
  if(stat(path,&_stat))
  {
    perror(path);
    return FAIL;
  }
  
  if(rflag)
    ftw(path,ftw_function,256);
  else
    ftw_function(path,&_stat,0);
  
 
  printf("signed %d file(s)\n",num_signed);

  return SUCCESS;
}


void print_help()
{ 
  puts("verihmac-sign [flags] [file|dir] [key(password)]");
  puts("flags: ");
  puts("-v  verbose, prints all  messages during signing");
  puts("-R  recursive signing");
  exit(FAIL);
} 

int ftw_function (const char *fpath, const struct stat *sb, int typeflag)
{	  
	if( (S_ISREG(sb->st_mode) || S_ISLNK(sb->st_mode)) && (sb->st_mode)&(S_IXUSR|S_IXGRP|S_IXOTH) )
	{
	   unsigned char buffer[MD_SIZE];

	   memset(buffer,0,MD_SIZE);	
	   if(!get_digest(fpath,(unsigned char*)&buffer))
	   {
	     if(setxattr(fpath,VERI_ATTR,&buffer,MD_SIZE,0)==-1)
	       perror("signing");
	     else 
	       num_signed++;
	   }
	}
	return SUCCESS;
}	 




int get_digest(const char * filename,unsigned char* buffer)
{
  int fd,bytes_read;
  unsigned int len; 
  HMAC_CTX ctx;
  unsigned char buf[FBUFLEN];
  
  fd = open(filename,O_RDONLY);
  
  if(fd<0){
    perror(filename);
    return FAIL;
  }
  
  HMAC_CTX_init(&ctx);
  HMAC_Init(&ctx,key,strlen(key),EVP_sha1());
  
  while((bytes_read=read(fd,buf,FBUFLEN))==FBUFLEN)
    HMAC_Update(&ctx,buf,FBUFLEN);
  
  HMAC_Update(&ctx,buf,bytes_read);
  
  if(HMAC_Final(&ctx,buffer,&len) )
  {
      if(verbose)
	{
	  int i;
	  printf("file:   %s    HMAC: ",filename);
	  for(i=0;i<len;i++)
	    printf("%02x",buffer[i] & 0x0FF);
	  puts("");
      }
  }
  
  HMAC_CTX_cleanup(&ctx);

  close(fd); 
  return SUCCESS;
}
