#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };
/* using at filesystem's race condition */
struct lock * filesys_lock;
/* process id. It is almost same with tid_t */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

static void syscall_handler (struct intr_frame *f);
void check_address(void *addr);
void halt (void); 
void exit (int status);
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* initilizing filesys_lock and 0x30 interrupt */
void
syscall_init (void) 
{
 
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);

}

/* It called when interrupt 0x30 is occur */
static void
syscall_handler (struct intr_frame *f) 
{
 /* p1 is user stack pointer saved at intr_frame
    we check p1 is user's address space and value of esp.   
  */
  uint32_t * p1 =(uint32_t*) f->esp;
  check_address((f->esp));
  int syscall_n=*p1;
  switch(syscall_n)
  { 
    /*
      When system call is occured, then stack top is system call's number.
      We can select system call using this value. 
      And check all argument of system call whether they are in user address 
      and valid.
      I set p1 by uint32_t pointer. So when we increase p1 by 1, then actually
      increase value by 4byte. 
      Therefore, the esp is adjusted in units of 4bytes to pass the stack
      value to the system call function.
      And save at f->eax system call's result. 
   */

    case SYS_HALT:
    halt();
    break;
    
    case SYS_EXIT:
    check_address((void*)(p1+1));
    exit(*(p1+1));
    break;
   
    case SYS_EXEC:
    check_address((void*)p1+1);
    f->eax=exec((const char*)*(p1+1));    
    break;
  
    case SYS_WAIT:
    check_address((void*)p1+1);
    f->eax=wait((pid_t)*(p1+1));
    break;

    case SYS_CREATE:
    check_address((void*)p1+1);
    check_address((void*)p1+2);
    f->eax=create((const char*)*(p1+1),(unsigned)*(p1+2));
    break;

    case SYS_REMOVE:
    check_address((void*)p1+1);
    f->eax=remove((const char*)*(p1+1));
    break;

    case SYS_OPEN:
    check_address((void*)p1+1);
    f->eax=open((const char*)*(p1+1));
    break;

    case SYS_FILESIZE:
    check_address((void*)p1+1);
    f->eax=filesize(*(p1+1));
    break;

    case SYS_READ:
    check_address((void*)p1+1);
    check_address((void*)p1+2);
    check_address((void*)p1+3);
    f->eax=read(*(p1+1),(void*)*(p1+2),(unsigned)*(p1+3));
    break;

    case SYS_WRITE:
    check_address((void*)p1+1);
    check_address((void*)p1+2);
    check_address((void*)p1+3);
    f->eax=write(*(p1+1),(void*)*(p1+2),(unsigned)*(p1+3));
    break;

    case SYS_SEEK:
    check_address((void*)p1+1);
    check_address((void*)p1+2);
    seek(*(p1+1),(unsigned)*(p1+2));
    break;


    case SYS_TELL:
    check_address((void*)p1+1);
    f->eax=tell(*(p1+1));
    break;

    case SYS_CLOSE:
    check_address((void*)p1+1);
    close(*(p1+1));
    break;
    default :
     exit(-1);
  }
}
/* check address whether this address is in user address */
void check_address(void *addr)
{
  if((is_kernel_vaddr(addr))||(addr<(void *)0x08048000UL))  
 { 
    exit(-1); 
  }
}

/* halt is just shut down pintos program */
void halt (void)
{
  shutdown_power_off();
}

/* exit is finishing current process and print exit status. */
void exit (int status)
{
 struct thread * t1 = thread_current();
 t1->exit_status = status;
 printf("%s: exit(%d)\n",t1->name,status);
 thread_exit();
}

/* 
   exec is kind of fork at the pintos. 
   It execute file by calling process execute.  
*/
pid_t exec (const char *file)
{
 pid_t child_pid;

 child_pid = process_execute(file);
 sema_down(&thread_current()->sema_load);   
 if(thread_current()->pr_success==false)
 return -1;

 return child_pid;  
}

/*
   wait pid's process is terminate.  
*/
int 
wait (pid_t pid)
{
  return (process_wait(pid)); 
}


/*
    create file by initial size.
*/
bool
create (const char * file, unsigned initial_size)
{ 
  if(file==NULL)
  exit(-1);
  check_address(file);   
   
  return (filesys_create(file, initial_size));
}

/*
    remove given file using filesys_remove.
*/
bool
remove (const char *file)
{ 
  
  return (filesys_remove(file));
}

/*
   open file is already created using filesys_open function. 
   It must deny write because it is opend by this thread. 
   And add filedescriptor of this thread.
*/
int open(const char * file)
{ 
 if(file==NULL)
 return -1;
 lock_acquire(&filesys_lock);
 struct file *f1 = filesys_open(file);
 if(strcmp(thread_current()->name,file)==0)
 file_deny_write(f1);
 int fd1 = process_add_file(f1);
 lock_release(&filesys_lock);
 return (fd1);
}

/*
   return filesize saved at filedescriptor.
   fd is index of filedescriptor.
*/
int filesize(int fd)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 return (-1);
 return (file_length(f1));
}

/*
   read file descriptor's file and save at buffer as size. 
   fd is stdinput, so we can implement using input_getc.
   If fd is not 0, we can implement using file_read function. 
   Equally, this function return reading file size. 
*/
int read(int fd, void * buffer, unsigned size)
{

 int i;
 check_address(buffer);
 lock_acquire(&filesys_lock); 
 if(fd==0)
 { 
  for(i=0; i<size; i++)
    { 
      ((uint8_t*)buffer)[i] = input_getc();
    }
    lock_release(&filesys_lock);
    return size;
 }
 else 
  { struct file * f1 = process_get_file(fd);
    if(f1==NULL)
    {
    lock_release(&filesys_lock);
    return -1;
    }
    file_read(f1,buffer,size);
    lock_release(&filesys_lock);

    return size;   
  }
 
}

/*
   Write at file from buffer. 
   If fd==1, then it is stdout. We can implement using putbuf.
   If fd=!1, we can implement using file_write and return size of write. 
*/
int write(int fd, void * buffer, unsigned size)
{
 
   lock_acquire(&filesys_lock); 
  if(fd==1)
  {  
   putbuf(buffer,size);
    lock_release(&filesys_lock);
   return size;
  }
  else
  {   struct file * f1 = process_get_file(fd);
   if(f1==NULL)
    {   
     lock_release(&filesys_lock);
     return -1;
    }
 
   size = file_write(f1,buffer,size);
   lock_release(&filesys_lock);
   return size;
  }
}

/*
   seek position at file in filedescriptor index fd
   and set file structure's position.
   we can implement this system call using file_seek.
*/

void seek(int fd, unsigned position)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 exit(-1);
 file_seek(f1,position);
}

/* 
    tell file position in filedescriptor's fdth file
*/
unsigned tell(int fd)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 exit(-1);
 return (file_tell(f1));
}
/*
    close file using process_close_file.
*/
void close(int fd)
{
   process_close_file(fd);
}

