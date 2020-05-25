/*C standard lib*/
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <errno.h> 

/*lib on Linux for operation of director*/
#include <dirent.h> 

/*syscall interface*/
#include <unistd.h> 
#include <sys/stat.h>


/*scan all the dir&files in a directory*/
void printdir(char *dir,int depth)
{
    DIR *dp;    
    struct dirent *entry;
    struct stat statbuf;

    if((dp = opendir(dir)) == NULL){
        fprintf(stderr,"cannot open directory: %s\n",dir);
        return;
    }   

    chdir(dir);

    while((entry = readdir(dp)) != NULL){
        lstat(entry->d_name,&statbuf);
        if(S_ISDIR(statbuf.st_mode)){
            /*Found a directory, but ignore . and .. */
            if(strcmp(".",entry->d_name) == 0 ||  
                strcmp("..",entry->d_name) == 0)
                continue;
            printf("%*s%s/\n",depth,"",entry->d_name); 

            /*Recurse at a new indent level*/
            printdir(entry->d_name, depth+4);
        }else{
            printf("%*s%s\n",depth,"",entry->d_name);
        }
    }
    chdir("..");
    closedir(dp);
}

int main()
{
    printf("Directory scan of /etc:\n");
    printdir("/etc",0);
    printf("done.\n");

    exit(0);
}



