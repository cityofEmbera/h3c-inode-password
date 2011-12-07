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

	// ��ӡ��������Ϣ
	printf("����������Ϣ\n\n");
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
		printf("%s\n", buf);			// UNICODE "��������" ��printf��ӡ������,Ҫת����ANSI

		WideCharToMultiByte(CP_ACP,
							0,
							pAdapList->Description,
							-1,
							buf,
							99,
							NULL,
							NULL);
		printf("%s\n", buf);

		printf("MAC��ַ: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
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
	printf("��ȡ����mac����,���ֶ���ȡ\n");
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
	printf("�ֶ���ȡHash����:\n");
	printf("�ļ�λ�� H3C��װĿ¼\\iNode Client\\Data\\8021\\*cfg.dat\n");
	printf("�û���ƫ��0x7b, ֻ��Ϊ���ֻ���ĸ\n");
	printf("����Hashƫ��0x229, ֻ��Ϊ��ĸ��'=','+', '/'\n\n");
	printf("�ü��±��������ļ�, ���Կ������� 6YwmTXWrzTw= ���ַ���\n");
	printf("һ��λ������ʱ��֮��, ע��Ҫ���ִ�Сд");
	printf("\n----------------------------------------------------------------\n\n");
	printf("����������Hash��\n");

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
			printf("�����Hash !!!\n\n");
		}
		else
		{
			printf("��Hash����Ӧ����Ϊ:%s\n", password);
			printf("\n");
		}
		printf("��������һ������Hash��\n");
	}while(TRUE);
}

int main()
{
	//BYTE user[USER_ACCOUNT_LENGTH];

	system("COLOR 0A"); 
	PrintAdapter();
	
	printf("\n                  Modified By CCAV\n\n");
	printf("-----------------------------------------------------\n\n");
	printf("���������ʼ��������\n");
	_getche();
	system("CLS"); 
	if(!ParaseH3CDataFile())
	{
		printf("���������ʼ�ֶ�����\n");
		printf("--------------------------------------------------------------------\n");
		_getche();
		system("CLS"); 
		ParaseByUser();
	}

	printf("��������˳�\n");
	_getche();
	return 0;
}