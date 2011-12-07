#include "decode.h"

#define PATH_TAIL_PATH						"\\Data\\8021\\?*.*"
#define PATH_TAIL_FILE_NAME					"?*.*"
#define MAX_USER_ACCOUNT_LEN				(USER_ACCOUNT_LENGTH + USER_ACCOUNT_LENGTH)

// ��ע���������H3C·��
DWORD FindH3CDataFilePath(PCHAR  pPath,				// ����·��
						  PDWORD  pcbPathLen)		// pPath��������С
{
	DWORD dwErr;
	HKEY h3c;
	DWORD dwRegType;
	DWORD len;
	PCHAR p;

	dwErr = RegOpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\H3C", &h3c);
	if(dwErr != ERROR_SUCCESS)
	{
		return dwErr;
	}

	dwRegType = REG_SZ;
	dwErr = RegQueryValueEx(h3c, "EAD1XINSTALLPATH", NULL, &dwRegType, NULL, &len);
	if(dwErr != ERROR_SUCCESS && dwErr != ERROR_BAD_LENGTH)
	{
		RegCloseKey(h3c);
		return dwErr;
	}
	if(len > *pcbPathLen || dwErr == ERROR_BAD_LENGTH || pPath == NULL)
	{
		RegCloseKey(h3c);
		*pcbPathLen = len + strlen(PATH_TAIL_PATH) + 1;
		return ERROR_BAD_LENGTH;
	}

	dwErr = RegQueryValueEx(h3c, "EAD1XINSTALLPATH", NULL, &dwRegType, pPath, &len);
	if(dwErr == ERROR_SUCCESS)
	{
		p = strrchr(pPath, '\\');
		if(p != NULL && *(p + 1) == '\0')
		{
			pPath[strlen(pPath) - 1] = '\0';
		}

		if(*pcbPathLen - len >= strlen(PATH_TAIL_PATH) + 1)
		{
			strcat_s(pPath, *pcbPathLen - 1, PATH_TAIL_PATH);
		}
		else
		{
			RegCloseKey(h3c);
			return ERROR_BAD_LENGTH;
		}
	}
	RegCloseKey(h3c);
	return dwErr;
}


// ��ָ���ļ��н�������
BOOL ParaseH3CFileInfoByPath(PCHAR  pFilePath)
{
	HANDLE hFile;
	CHAR user[MAX_USER_ACCOUNT_LEN];			// ѧ��Ӧ����8����,���һ��.
	DWORD dwRead;
	CHAR encrypt[USER_PASSWORD_LENGTH];			// ʵ�ʵļ��ܺ�����볤�ȳ��������
	CHAR password[USER_PASSWORD_LENGTH];		// ԭ���벻�ᳬ�����ܺ�������3/4
	DWORD dwErr;
	DWORD dwPassLen;
	int i;

	hFile = CreateFile(pFilePath,
					   GENERIC_READ,
					   FILE_SHARE_READ | FILE_SHARE_WRITE,
					   NULL,
					   OPEN_EXISTING,
					   FILE_ATTRIBUTE_NORMAL,
					   NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	dwErr = SetFilePointer(hFile,
						   0x7b,		// �ʺ�ƫ��
						   NULL,
						   FILE_BEGIN);
	if(INVALID_SET_FILE_POINTER == dwErr)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	RtlZeroMemory(user, USER_ACCOUNT_LENGTH);
	if(!ReadFile(hFile, 
				 user,
				 MAX_USER_ACCOUNT_LEN - 1,
				 &dwRead,
				 NULL))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	
	// �����û���
	for(i = 0; i < MAX_USER_ACCOUNT_LEN; i++)
	{
		if(user[i] < '0' || (user[i] > '9' && user[i] < 'A') ||
			(user[i] > 'Z' && user[i] < 'a') || user[i] > 'z')
		{
			user[i] = '\0';
			break;
		}
	}

	dwErr = SetFilePointer(hFile,
						   0x229,		// ������ƫ��
						   NULL,
						   FILE_BEGIN);
	
	RtlZeroMemory(encrypt, USER_PASSWORD_LENGTH);
	if(!ReadFile(hFile,
				 encrypt,
				 USER_PASSWORD_LENGTH,
				 &dwRead,
				 NULL))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	
	// encrypt���Ƕ�ȡ������base64��
	dwPassLen = USER_PASSWORD_LENGTH - 1;
	RtlZeroMemory(password, USER_PASSWORD_LENGTH);
	if(0 != DecodeINodeP(encrypt,						// ����ֵ������Ϊ1
						 strlen(encrypt), 
						 password, 
						 &dwPassLen))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// ���һ������,ֱ�Ӵ�ӡ����,͵����
	printf("\n�����ʺ�\n");
	printf("�ʺ�:%s\n", user);
	printf("����:%s\n\n", password);

	CloseHandle(hFile);
	return TRUE;
}

BOOL ParaseH3CDataFile()
{
	HANDLE hFind;

	PCHAR pFilePath;
	CHAR TempPath[MAX_PATH];	// ����͵��

	PCHAR p;
	DWORD dwPathLen;
	WIN32_FIND_DATA wfd;
	BOOL bRet;

	if(ERROR_BAD_LENGTH != FindH3CDataFilePath(NULL, &dwPathLen))
	{
		printf("\n--------------------------------------------------------------------\n");
		printf("δ�ҵ�H3C,���ֶ������ļ�\n\n");
		return FALSE;
	}
	pFilePath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPathLen);
	if(pFilePath == NULL)
	{
		printf("\n--------------------------------------------------------------------\n");
		printf("δ�ҵ�H3C,���ֶ������ļ�\n\n");
		return FALSE;
	}
	if(ERROR_SUCCESS != FindH3CDataFilePath(pFilePath, &dwPathLen))	// dwPathLenƫ���˵�.����Ӱ��.
	{
		printf("\n--------------------------------------------------------------------\n");
		printf("δ�ҵ�H3C,���ֶ������ļ�\n\n");
		HeapFree(GetProcessHeap(), 0, pFilePath);
		return FALSE;
	}
	if(dwPathLen > MAX_PATH - strlen(PATH_TAIL_FILE_NAME) - 10)
	{
		printf("\n--------------------------------------------------------------------\n");
		printf("H3C��װĿ¼����,���ֶ������ļ�\n\n");
		HeapFree(GetProcessHeap(), 0, pFilePath);
		return FALSE;
	}
	
	strcpy_s(TempPath, MAX_PATH - 1, pFilePath);
	//TempPath[strlen(pFilePath) - strlen(PATH_TAIL_FILE_NAME)] = '\0';
	
	hFind = FindFirstFile(pFilePath, &wfd);
	if(INVALID_HANDLE_VALUE == hFind)
	{
	printf("\n--------------------------------------------------------------------\n");
	printf("δ�ҵ�H3C,���ֶ������ļ�\n\n");
		HeapFree(GetProcessHeap(), 0, pFilePath);
		return FALSE;
	}
	strcat_s(TempPath, MAX_PATH - 1, wfd.cFileName); 
	if(wfd.cFileName[0] != '.' && strcmp(wfd.cFileName, ".."))
	{
		if(!ParaseH3CFileInfoByPath(TempPath))
		{
			printf("����[%s]�ļ�ʧ��,����δ��¼����,���ֶ��������ļ�\n\n", TempPath);
			HeapFree(GetProcessHeap(), 0, pFilePath);
			FindClose(hFind);
			return FALSE;
		}
	}

	bRet = TRUE;
	while(FindNextFile(hFind, &wfd))
	{
		if(wfd.cFileName[0] == '.' || 0 == strcmp(wfd.cFileName, ".."))
		{
			continue;
		}

		p = strrchr(TempPath, '\\');
		if(p == NULL)
		{
			HeapFree(GetProcessHeap(), 0, pFilePath);
			return FALSE;
		}
		*(p + 1) = '\0';
		strcat_s(TempPath, MAX_PATH - 1, wfd.cFileName); 
		if(!ParaseH3CFileInfoByPath(TempPath))
		{
			bRet = FALSE;
			printf("����[%s]�ļ�ʧ��,����δ��¼����,���ֶ��������ļ�\n\n", TempPath);
		}
	}

	HeapFree(GetProcessHeap(), 0, pFilePath);
	FindClose(hFind);
	return bRet;
}
