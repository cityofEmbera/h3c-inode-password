#pragma once
#ifdef UNICODE
#undef UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>


int DecodeINodeP(char *Base64Hash,
				 size_t HashLen, 
				 char *Password, 
				 size_t OPTIONAL *PassSize);




ParaseH3CDataFile();

#define USER_ACCOUNT_LENGTH					(8 + 1)
#define USER_PASSWORD_LENGTH				(64 + 1)