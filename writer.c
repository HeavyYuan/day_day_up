/*
 *Function: produce rand length strings
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

char src[]="ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define RAND_STEP 10
#define LEN_MOD (sizeof(src))

typedef struct data{
    int len;
    char str[0];
}Data;

#define mem_free(p)     \
    do{                 \
        if(p){          \
            free(p);    \
            p = NULL;   \
        }               \
    }while(0)

int data_produce(struct data *);
int data_write(struct data *, int);
int data_read(struct data *, int);
int data_check(struct data *, struct data *);

int rand_len()
{
    time_t t;
    int rnum = 0;
    srand((unsigned)time(&t));
    rnum = rand() % LEN_MOD;
    if(rnum < RAND_STEP)
        rnum=rnum + RAND_STEP;

    return(rnum);

}

int rand_pos(int mod, int *pos_arr)
{
    time_t t;
    int i;
    srand((unsigned)time(&t));
    for(i=0; i < mod; i++)
    {
        int rnum = rand() % mod;
        pos_arr[i] = rnum;

    }
    return(0);
    
}

Data *mem_alloc(int d_len){
    
    int true_size;
    Data *p = NULL;

    true_size = sizeof(struct data) + d_len;
    p = (struct data *)malloc(true_size);
    if(!p)
        return NULL;

    return p;
}


int data_produce(struct data *in)
{
    int len,i;

    len = in->len;
    int *pos = (int *)malloc(sizeof(int) * len);
    char *str = (char *)malloc(sizeof(char) * len);

    rand_pos(len,pos);
    for(i = 0; i < len; i++)
    {
       str[i] = src[pos[i]];
    }

    memcpy(in->str,str,in->len);
    in->str[len] = '\0';
    
    free(pos);
    free(str);

    return 0;

}

int data_write(struct data *in,int d_len){
    
    FILE *fp = fopen("datafile", "w+");

    if( !fp )
    {
        printf("open error\n");
        return 1;
    }

    fwrite(in, sizeof(struct data) + d_len,1,fp);
    fclose(fp);
}

int data_read(struct data *out, int d_len)
{
   FILE *fp = fopen("datafile","r");
   if( !fp )
   {
        printf("open error for read\n");
        return 1;
   }

   fread(out,sizeof(struct data) + d_len,1,fp);
   fclose(fp);


}

int data_check(struct data *in, struct data *out){

    
    int len_flag = 0;
    int content_flag = 0;
    if(in->len != out->len)
    {
       len_flag = 1;
    }
    if(strncmp(in->str,out->str,in->len)!=0)
    {
       content_flag = 1;
    }
    
    if(len_flag == 1 || content_flag ==1 )
    {

    FILE *fp = fopen("result", "a");
    if( !fp  )
    {
        printf("open failed for check\n");
        return(1);
    }
    if( len_flag == 1 ){
        fprintf(fp,"write data len: %d,\tread data len: %d\n",in->len,out->len);
        fflush(fp);
    }

    if(content_flag == 1 ){
        fprintf(fp,"write data: %s,\tread data: %s\n",in->str,out->str);
        fflush(fp);
    }

    fclose(fp);

    }
    return(0);
}

int main()
{
    while(1){

        Data *in = NULL;
        Data *out = NULL;

        int d_len = rand_len();
        in = mem_alloc(d_len + 1); //1 byte for '\0'
        if (!in){
            printf("mem_alloc failed\n");
            exit(1);
        }
        in->len = d_len;

        data_produce(in);
        data_write(in,d_len);
        printf("data_write: %d, %s\n", in->len,in->str);

        usleep(1000);

        out = (struct data *)mem_alloc(d_len + 1); // size of 'in' = size of 'out'
        if (!out){
            printf("mem_alloc failed\n");
            exit(1);
        }
        data_read(out,d_len);
        printf("data_read: %d, %s\n", out->len,out->str);

        data_check(in, out);

        mem_free(in);
        mem_free(out);
        
    }

    return(0);
}
