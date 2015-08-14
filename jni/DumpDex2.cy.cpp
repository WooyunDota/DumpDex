#include "substrate.h"
#include <android/log.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <cstdlib>
#include "DumpDex2.cy.h"
#include "base64.h"


//http://androidxref.com/4.4.4_r1/xref/frameworks/base/core/java/android/app/ActivityThread.java#4861
const char* ex0 = "<pre-initialized>";  //对应没脱壳的 odex 文件, UI 线程的 tag

const char* ex1 = "zygote";
const char* ex2 = "app_process";
const char* ex3 = "/system/bin/dexopt";
const char* ex4 = "com.google.android.gms";
const char* ex5 = "com.google.android.gms.persistent";
const char* ex6 = "com.google.process.gapps";
const char* ex7 = "com.google.android.gms.wearable";
const char* ex8 = "com.android.phone";
const char* ex9 = "com.android.systemui";
const char* ex10 = "com.google.android.gms.unstable";
const char* ex11 = "android.process.acore";
const char* ex12 = "android.process.media";


const char* workDir = "/sdcard/mydex/";

int exclude(char* s){

	int i ;
	//
	i = !strcmp(s,ex0)||!strcmp(s,ex1)||!strcmp(s,ex2)||!strcmp(s,ex3)||\
		!strcmp(s,ex4)||!strcmp(s,ex5)||!strcmp(s,ex6)||!strcmp(s,ex7)||\
		!strcmp(s,ex8)||!strcmp(s,ex9)||!strcmp(s,ex10)||!strcmp(s,ex11)||\
		!strcmp(s,ex12);

	return i;
}

//get packagename from pid
int getProcessName(char * buffer){
    char path_t[256]={0};
    pid_t pid=getpid();
    char str[15];
    sprintf(str, "%d", pid);
    memset(path_t, 0 , sizeof(path_t));
    strcat(path_t, "/proc/");
    strcat(path_t, str);
    strcat(path_t, "/cmdline");
    int fd_t = open(path_t, O_RDONLY);
    if(fd_t>0){
        int read_count = read(fd_t, buffer, BUFLEN);

        if(read_count>0){
              int  processIndex=0;
              for(processIndex=0;processIndex<strlen(buffer);processIndex++){
                  if(buffer[processIndex]==':'){
                      buffer[processIndex]='_';
                  }

              }
            return 1;
        }
    }
    return 0;
}

//检查文件夹是否存在，不存在则创建
int checkDir()
{

	 mode_t myMode = 777 ;

	if(0 == access(workDir,0)) {//目录存在
		return 0;
	} else{
		if(0 == mkdir(workDir,myMode)) {
			return 0;
		}
		else {
			return 1;
		}
	};
}

//指定要hook 的 lib 库
MSConfig(MSFilterLibrary,"/system/lib/libdvm.so")


//保留原来的地址  DexFile* dexFileParse(const u1* data, size_t length, int flags)
DexFile* (* oldDexFileParse)(const u1* data, size_t length, int flags);

//替换的函数,导出dex文件
DexFile* myDexFileParse(const u1 * addr,size_t len,int dvmdex)
{
	//LOGD("call myDexFileParse! : %d",getpid());

	{
		/*
		 * bufferProcess: processname
		 * dexbuffer: _dump_len
		 * dexbufferNamed: /sdcard -> /sdcard/processname -> /sdcard/processname_dump_len
		 *
		 */
	    char dexbuffer[64]={0};
	    char dexbufferNamed[128]={0};
		char * bufferProcess=(char*)calloc(256,sizeof(char*));

		//得到 processname
		int  processStatus= getProcessName(bufferProcess);
		LOGD("call myDexFileParse! pid: %d , pname : %s , size : %d ",getpid(),bufferProcess,len);

		// 对 processname 进行排除

		if(exclude(bufferProcess)){
			LOGI("exclude shoot");
			return oldDexFileParse(addr,len,dvmdex);
		}
		else
			LOGI("continue");

		//创建目录
		if(checkDir())
			LOGD("Dir /sdcard/mydex/ not exit and create it failed, please check it!");

//		对 pre-init 进行 pid 拼接
//		if(!strcmp(bufferProcess,ex0))
//			sprintf(dexbuffer, "_pid_%d", getpid());
//		else
		sprintf(dexbuffer, "_%d", len);

	    strcat(dexbufferNamed,"/sdcard/mydex/");
	    if (processStatus==1) {
	      strcat(dexbufferNamed,bufferProcess);
	      strcat(dexbufferNamed,dexbuffer);

	    }else{
	    	LOGD("FAULT pid not  found\n");
	    }

	    if(bufferProcess!=NULL)
	    {

	      free(bufferProcess);
	    }

	    //正常写文件
	    strcat(dexbufferNamed,".dex");
		FILE * f=fopen(dexbufferNamed,"wb");
		if(!f)
		{
			LOGD("%s : error open sdcard file to write ",dexbufferNamed);
		}
		else{
			fwrite(addr,1,len,f);
			fclose(f);
			LOGD("%s : dump well~ ",dexbufferNamed);
		}

		//base64后写入文件.Anti bangbang hook write function
		//解码: base64 -D -i com.ali.tg.testapp_606716.dex.encode.dex -o my.dex
		// base64 -d com.ali.tg.testapp_606716.dex.encode.dex > my.dex
		strcat(dexbufferNamed,".encode.dex");
		FILE * fp=fopen(dexbufferNamed,"wb");
		if(!fp){
			LOGD("create file failed");
		}else{
			unsigned char *dst=(unsigned char*)malloc(len*2.5);
			unsigned int dlen=len*2.5;
			//int base64_encode( unsigned char *dst, size_t *dlen, const unsigned char *src, size_t )
			//int base64_encode(unsigned char *, unsigned int *, const unsigned char *, unsigned int)
			base64_encode(dst, &dlen, addr, len);
			fwrite(dst, dlen, 1, fp);
			fclose(fp);
			fp = NULL;
		}


	}
	//进行原来的调用，不影响程序运行
	return oldDexFileParse(addr,len,dvmdex);
}

//Substrate entry point
MSInitialize
{
    LOGD("Cydia Init");
    MSImageRef image;
    //载入lib
    image = MSGetImageByName("/system/lib/libdvm.so");
    if (image != NULL)
    {
        void * dexload=MSFindSymbol(image,"_Z12dexFileParsePKhji");
        if(dexload==NULL)
        {
            LOGD("error find _Z12dexFileParsePKhji");

        }
        else{
        	//替换函数
        	//3.MSHookFunction
            MSHookFunction(dexload,(void*)&myDexFileParse,(void **)&oldDexFileParse);
        }
    }
    else{
        LOGD("ERROR FIND LIBDVM");
    }
}




