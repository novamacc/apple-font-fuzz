#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);
static void alrm(int s) { printf("Time limit reached\n"); _exit(0); }
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s corpus_dir/\n", argv[0]); return 1; }
    int max_time = 18000;
    for (int i=2;i<argc;i++) {
        if (strncmp(argv[i],"-max_total_time=",16)==0) max_time=atoi(argv[i]+16);
    }
    signal(SIGALRM, alrm); alarm(max_time);
    srand(time(NULL));
    int iters=0; time_t start=time(NULL);
    while(1) {
        DIR *d=opendir(argv[1]); if(!d) break;
        struct dirent *e; int cnt=0;
        while((e=readdir(d))) if(e->d_name[0]!='.') cnt++;
        if(cnt==0){closedir(d);break;}
        int tgt=rand()%cnt; rewinddir(d); int idx=0; char path[1024];
        while((e=readdir(d))){if(e->d_name[0]=='.')continue;if(idx==tgt){snprintf(path,sizeof(path),"%s/%s",argv[1],e->d_name);break;}idx++;}
        closedir(d);
        FILE *f=fopen(path,"rb");if(!f)continue;
        fseek(f,0,SEEK_END);size_t sz=ftell(f);fseek(f,0,SEEK_SET);
        unsigned char *buf=malloc(sz+256);size_t rd=fread(buf,1,sz,f);fclose(f);
        for(int m=0;m<1+rand()%5;m++){
            if(rd==0)break;
            int op=rand()%3;
            if(op==0)buf[rand()%rd]^=(1<<(rand()%8));
            else if(op==1)buf[rand()%rd]=rand()%256;
            else if(rd<sz+200){size_t p=rand()%(rd+1);memmove(buf+p+1,buf+p,rd-p);buf[p]=rand()%256;rd++;}
        }
        LLVMFuzzerTestOneInput(buf,rd);free(buf);iters++;
        if(iters%10000==0)printf("[%lds] %d iters\n",time(NULL)-start,iters);
    }
    printf("Done: %d iters in %lds\n",iters,time(NULL)-start);
    return 0;
}
