#include <linux/module.h>	
#include <linux/kernel.h>	
#include <linux/init.h>	
#include <linux/sysfs.h>
#include <linux/security.h>
#include <linux/err.h>
#include <linux/xattr.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/moduleparam.h>
#include <linux/mman.h> 
#include <linux/gfp.h>
#include <crypto/hash.h>


#define VERBOSE_MODE 1
#define BLOCKING_MODE 2


#define SYSFSNAME "verihmac"
#define VERI_INFO KERN_INFO "verihmac:" 
#define VERI_ERROR KERN_ERR "verihmac:"


#define VERI_HMAC "hmac(sha1)"
#define MD_SIZE 20



static int     create_sysf_files(void);
static char    *password_str;
static int     password_len;
static int     active=0; 
static int     isloaded=0;

static ssize_t password_show(struct kobject *kobj, struct kobj_attribute *attr,	char *buf);
static ssize_t password_store(struct kobject *kobj, struct kobj_attribute *attr,char *buf, size_t count);

static ssize_t mode_show(struct kobject *kobj, struct kobj_attribute *attr,	char *buf);
static ssize_t mode_store(struct kobject *kobj, struct kobj_attribute *attr,char *buf, size_t count);

static int verihmac_calc_hash(struct file* file,char *digest);
static int verihmac_file_mmap(struct file *file, unsigned long reqprot,unsigned long prot, unsigned long flags,
			unsigned long addr, unsigned long addr_only);
static int verihmac_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,unsigned long prot);
static int verihmac_verify_file(struct file * file);


/*Structures*/
static struct kobj_attribute password_attribute =__ATTR(password, 0600, password_show, password_store);
static struct kobj_attribute mode_attribute =__ATTR(mode, 0600, mode_show, mode_store);
	
static struct security_operations verihmac_security_ops = {
	 .name 		      ="verihmac",
         .file_mmap	      =verihmac_file_mmap,
         .file_mprotect       =verihmac_file_mprotect,
};

static struct srcu_struct verihmac_ss;



static int __init init_verihmac(void)
{
	
	if (!security_module_enable(&verihmac_security_ops))
		return 0;
	
	if (register_security(&verihmac_security_ops) ||
	    init_srcu_struct(&verihmac_ss))
		panic("Failure registering Verihmac Linux");
	printk(VERI_INFO "verihmac Linux initialized\n");
	isloaded =1;
	return 0;
}




	
static int __init create_sysf_files(void)
{
	struct kobject* root_kobject;
	//fs initcall jest wywolywany nawet gdy modul jest nieaktywny wie jezeli nieaktywny to nie towrzymy sysfs 
	if(!isloaded)
	    return 0;
	    
	root_kobject = kobject_create_and_add(SYSFSNAME, kernel_kobj);
	
	if (!root_kobject)
		return -ENOMEM;
	
	if(sysfs_create_file(root_kobject,(struct attribute*)&password_attribute)!=0)
	{
	  return -1;
	}

	if(sysfs_create_file(root_kobject,(struct attribute*)&mode_attribute)!=0)
	{
	  return -1;
	}
	
	printk(KERN_INFO "verihmac SYSFS initialized \n");
	return 0;
} 


static ssize_t password_show(struct kobject *kobj, struct kobj_attribute *attr,	char *buf)
{
    return  sprintf(buf,"password is write only\n");
}


static ssize_t password_store(struct kobject *kobj, struct kobj_attribute *attr,char *buf, size_t count)
{
  if(active) return count; 
  
  active = VERBOSE_MODE;
  password_str = (char*)kmalloc(sizeof(char)*count+1,GFP_KERNEL);
  password_str[count]=0;
  password_len = count;
  sscanf(buf,"%s",password_str);
  
  return count; 
}


static ssize_t mode_show(struct kobject *kobj, struct kobj_attribute *attr,	char *buf)
{
    return  sprintf(buf,"current protection level: %d\n",active);
}


static ssize_t mode_store(struct kobject *kobj, struct kobj_attribute *attr,char *buf, size_t count)
{
  if(active==BLOCKING_MODE  || active == 0) return count; 
  else{
    int tmp = 0;
    sscanf(buf,"%d",&tmp);
    if(tmp==BLOCKING_MODE)
      active=BLOCKING_MODE;
  }
  
  return count; 
}


static int verihmac_file_mmap(struct file *file, unsigned long reqprot,unsigned long prot, unsigned long flags,
			unsigned long addr, unsigned long addr_only)
{
  if(active)
  {    
    //anonimowe nas nie interesują
    if(flags & MAP_ANONYMOUS ) 
      return 0; 
    
    //jezeli nie jest to mapowanie wykonywalnych to tez nas nei interesuje
    if(!(prot & PROT_EXEC ))
      return 0;

    
    if(verihmac_verify_file(file))
    {
      if(active == VERBOSE_MODE)
	printk(VERI_ERROR "invalid hmac %s\n",file->f_path.dentry->d_name.name);
      else 
	return -EPERM;
    }
      
    return 0;
      
  }	  
  
  return 0;
}


static int verihmac_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,unsigned long prot)
{
  if(vma->vm_file && (reqprot & PROT_EXEC)){ 
        
    if(verihmac_verify_file(vma->vm_file))
    {
      if(active == VERBOSE_MODE)
	printk(VERI_ERROR "invalid hmac %s\n",vma->vm_file->f_path.dentry->d_name.name);
      else 
	return -EPERM;
    }
  }
 
  return 0;
}


static int verihmac_calc_hash(struct file* file,char* digest)
{
	struct hash_desc desc;
	struct scatterlist sg;

	int rc;
	char *rbuf;

	loff_t i_size, offset = 0;
	
	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf) {
	        printk(VERI_ERROR "no free memory\n");
		rc = -ENOMEM;
		return rc;
	}
	
	desc.tfm = crypto_alloc_hash(VERI_HMAC, 0,CRYPTO_ALG_ASYNC);
	
	if (IS_ERR(desc.tfm)) {
		printk(VERI_ERROR "failed to load %s transform: %ld\n",
			VERI_HMAC, PTR_ERR(desc.tfm));
		rc = PTR_ERR(desc.tfm);
		kfree(rbuf);
		return rc;
	}
	
	desc.flags = 0;
	
       if(crypto_hash_setkey(desc.tfm,password_str,password_len)!=0) { 
	  printk(VERI_ERROR "setting key error  \n");
	  kfree(rbuf);
	  crypto_free_hash(desc.tfm);
	  return -1;
	}
	
	rc=crypto_hash_init(&desc);   
	
	if(rc)
	{
	  printk(VERI_ERROR "hash_init failed \n");
	  crypto_free_hash(desc.tfm);
	  kfree(rbuf);
	  return rc;
	}
	
	i_size = i_size_read(file->f_dentry->d_inode);
	
	while (offset < i_size) {
		int rbuf_len;
		rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
		
		if (rbuf_len < 0) {
			rc = rbuf_len;
			break;
		}
		
		if (rbuf_len == 0)
			break;
		
		offset += rbuf_len;
		
		sg_set_buf(&sg, rbuf, rbuf_len);
		rc = crypto_hash_update(&desc, &sg, rbuf_len);
		
		if (rc)
			break;
	}

	kfree(rbuf);
	if (!rc)
		rc = crypto_hash_final(&desc, digest);
	
	crypto_free_hash(desc.tfm);
	return rc;
}



static int verihmac_verify_file(struct file * file)
{
	struct dentry* file_dentry;
	struct inode*  inode;
	char attr_buffer[MD_SIZE];
	char HMAC_hash[MD_SIZE];
        int size,i;
	


	file_dentry= file->f_path.dentry;     
	inode = file_dentry->d_inode;


	if (!inode || !inode->i_op->getxattr)
     		 return 1; 
     	
   
     	size = inode->i_op->getxattr(file_dentry,"security.verihmac",NULL,0);

    	if(size == -ENODATA ) 
	  return 1;

    	else 
    	if(size > 0) 
    	{	
      		inode->i_op->getxattr(file_dentry,"security.verihmac",attr_buffer,size);
		
		for(i = 0 ; i < MD_SIZE;i++)
		  HMAC_hash[i]=0;
		
      		verihmac_calc_hash(file,HMAC_hash);
	
		for(i = 0; i< MD_SIZE ;i++)
		{
			if( attr_buffer[i] !=HMAC_hash[i])
				return 1;
		}		
    	}  
  return 0;
}

//BINDINGS
security_initcall (init_verihmac);
fs_initcall(create_sysf_files);



MODULE_LICENSE("GPL");

MODULE_AUTHOR("Pawel Pikula ppikula@gmail.com");	
MODULE_DESCRIPTION("Module monitoring all memory mappings, prevents untrusted files to be mapped in memory for execution");
