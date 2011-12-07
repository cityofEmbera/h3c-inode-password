#include <stdio.h>
#include <conio.h>
#include "decode.h"
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")

BOOL PrintAdapter()
{
	PIP_ADAPTER_ADDRESSES pAdapterAddr, pAdapList;
	DWORD dwLen;
	DWORD dwRet;
	CHAR buf[100];

	pAdapterAddr = NULL;

	dwRet = GetAdaptersAddresses(AF_INET,
								 0,
								 NULL,
								 NULL,
								 &dwLen);
	if(ERROR_BUFFER_OVERFLOW != dwRet)
	{
		goto ERROR_LEAVE;
	}

	pAdapterAddr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
	if(pAdapterAddr == NULL)
	{
		goto ERROR_LEAVE;
	}

	if(ERROR_SUCCESS != GetAdaptersAddresses(AF_INET,
											 0,
											 NULL,
											 pAdapterAddr,
											 &dwLen))
	{
		goto ERROR_LEAVE;
	}

	// 打印各网卡信息
	printf("本机网卡信息\n\n");
	for(pAdapList = pAdapterAddr;
		pAdapList != NULL; 
		pAdapList = pAdapList->Next)
	{
		WideCharToMultiByte(CP_ACP,
							0, 
							pAdapList->FriendlyName,
							-1,
							buf,
							99,
							NULL,
							NULL);
		printf("%s\n", buf);			// UNICODE "本地连接" 用printf打印不出来,要转换成ANSI

		WideCharToMultiByte(CP_ACP,
							0,
							pAdapList->Description,
							-1,
							buf,
							99,
							NULL,
							NULL);
		printf("%s\n", buf);

		printf("MAC地址: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
				pAdapList->PhysicalAddress[0], pAdapList->PhysicalAddress[1],
				pAdapList->PhysicalAddress[2], pAdapList->PhysicalAddress[3],
				pAdapList->PhysicalAddress[4], pAdapList->PhysicalAddress[5],
				pAdapList->PhysicalAddress[6], pAdapList->PhysicalAddress[7]);
		printf("\n");
	}
	printf("-----------------------------------------------------\n");

	HeapFree(GetProcessHeap(), 0, pAdapterAddr);
	return TRUE;

ERROR_LEAVE:
	printf("获取网卡mac出错,请手动获取\n");
	if(pAdapterAddr != NULL)
	{
		HeapFree(GetProcessHeap(), 0, pAdapterAddr);
	}
	return FALSE;
}

void ParaseByUser()
{
	BYTE password[USER_PASSWORD_LENGTH];
	BYTE hash[USER_PASSWORD_LENGTH];
	size_t len = USER_PASSWORD_LENGTH - 1;


	printf("\n----------------------------------------------------------------\n");
	printf("手动提取Hash方法:\n");
	printf("文件位置 H3C安装目录\\iNode Client\\Data\\8021\\*cfg.dat\n");
	printf("用户名偏移0x7b, 只能为数字或字母\n");
	printf("密码Hash偏移0x229, 只能为字母或'=','+', '/'\n\n");
	printf("用记事本打开上述文件, 可以看到形如 6YwmTXWrzTw= 的字符串\n");
	printf("一般位于两个时间之间, 注意要区分大小写");
	printf("\n----------------------------------------------------------------\n\n");
	printf("请输入密码Hash：\n");

	do
	{
		RtlZeroMemory(hash, USER_PASSWORD_LENGTH);
		fflush(stdin);
		scanf_s("%s", hash, USER_PASSWORD_LENGTH - 4);
		if(hash[0] == '!')
		{
			break;
		}

		if(0 != DecodeINodeP(hash, 
			strlen(hash),
			password, 
			&len))
		{
			printf("错误的Hash !!!\n\n");
		}
		else
		{
			printf("该Hash所对应密码为:%s\n", password);
			printf("\n");
		}
		printf("请输入下一个密码Hash：\n");
	}while(TRUE);
}

int main()
{
	//BYTE user[USER_ACCOUNT_LENGTH];

	system("COLOR 0A"); 
	PrintAdapter();
	
	printf("\n                  Modified By CCAV\n\n");
	printf("-----------------------------------------------------\n\n");
	printf("按任意键开始分析密码\n");
	_getche();
	system("CLS"); 
	if(!ParaseH3CDataFile())
	{
		printf("按任意键开始手动解析\n");
		printf("--------------------------------------------------------------------\n");
		_getche();
		system("CLS"); 
		ParaseByUser();
	}

	printf("按任意键退出\n");
	_getche();
	return 0;
}