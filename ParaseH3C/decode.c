#include "decode.h"

/*
*	解析DATA\8021\xcfg.dat, 这个只能静态解析.如果不保存密码的,则没有办法
*	X1Face.dll + 0CEA7 出现了用户名
*	X1Face.dll + 0CE09 出现了密码
*   可以patch X1Face.dll用以记录登录过的帐号密码等信息.
*   其实h3c_utility.dll里边导出了解密函数...到最后才发现...
*/

#define TABLE_LEN			128

void DecodePhase2(int code[2]);
void DecodePhase1(int EncryptAddress[2], char Password[8]);


// call sub_10010110里边使用到的数组,有可能抄错....如果解码错误就说明抄错了..
const int table1[64] = {0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000, 
						0x400,      0x1010400,  0x1010404,  0x400,      0x1000404,  0x1010004,  0x1000000,  0x4, 
						0x404,      0x1000400,  0x1000400,  0x10400,    0x10400,    0x1010000,  0x1010000,	0x1000404,
						0x10004,    0x1000004,  0x1000004,  0x10004,    0x0,        0x404,		0x10404,    0x1000000,
						0x10000,    0x1010404,  0x4,        0x1010000,  0x1010400,  0x1000000,  0x1000000,  0x400, 
						0x1010004,  0x10000,    0x10400,    0x1000004,  0x400,      0x4,        0x1000404,  0x10404, 
						0x1010404,  0x10004,    0x1010000,  0x1000404,  0x1000004,  0x404,      0x10404,    0x1010400,
						0x404,      0x1000400,  0x1000400,  0x0,        0x10004,    0x10400,    0x0,        0x1010004};

const int table2[64] = {0x208,      0x8020200,  0x0,        0x8020008,  0x8000200,  0x0,        0x20208,    0x8000200,
						0x20008,    0x8000008,  0x8000008,  0x20000,    0x8020208,  0x20008,    0x8020000,  0x208,
						0x8000000,  0x8,        0x8020200,  0x200,      0x20200,    0x8020000,  0x8020008,  0x20208,
						0x8000208,  0x20200,    0x20000,    0x8000208,  0x8,        0x8020208,  0x200,      0x8000000,
						0x8020200,  0x8000000,  0x20008,    0x208,      0x20000,    0x8020200,  0x8000200,  0x0, 
						0x200,      0x20008,    0x8020208,  0x8000200,  0x8000008,  0x200,      0x0,        0x8020008,
						0x8000208,  0x20000,    0x8000000,  0x8020208,  0x8,        0x20208,    0x20200,    0x8000008, 
						0x8020000,  0x8000208,  0x208,      0x8020000,  0x20208,    0x8,        0x8020008,  0x20200};

const int table3[64] = {0x100,      0x2080100,  0x2080000,  0x42000100, 0x80000,    0x100,      0x40000000, 0x2080000,
						0x40080100, 0x80000,    0x2000100,  0x40080100, 0x42000100, 0x42080000, 0x80100,    0x40000000,
						0x2000000,  0x40080000, 0x40080000, 0x0,        0x40000100, 0x42080100, 0x42080100, 0x2000100,
						0x42080000, 0x40000100, 0x0,        0x42000000, 0x2080100,  0x2000000,  0x42000000, 0x80100,
						0x80000,    0x42000100, 0x100,      0x2000000,  0x40000000, 0x2080000,  0x42000100, 0x40080100,
						0x2000100,  0x40000000, 0x42080000, 0x2080100,  0x40080100, 0x100,      0x2000000,  0x42080000,
						0x42080100, 0x80100,    0x42000000, 0x42080100, 0x2080000,  0x0,        0x40080000, 0x42000000,
						0x80100,    0x2000100,  0x40000100, 0x80000,    0x0,        0x40080000, 0x2080100,  0x40000100};

const int table4[64] = {0x200000,   0x4200002,  0x4000802,  0x0,        0x800,      0x4000802,  0x200802,   0x4200800, 
						0x4200802,  0x200000,   0x0,        0x4000002,  0x2,        0x4000000,  0x4200002,  0x802,
						0x4000800,  0x200802,   0x200002,   0x4000800,  0x4000002,  0x4200000,  0x4200800,  0x200002, 
						0x4200000,  0x800,      0x802,      0x4200802,  0x200800,   0x2,        0x4000000,  0x200800, 
						0x4000000,  0x200800,   0x200000,   0x4000802,  0x4000802,  0x4200002,  0x4200002,  0x2,
						0x200002,   0x4000000,  0x4000800,  0x200000,   0x4200800,  0x802,      0x200802,   0x4200800, 
						0x802,      0x4000002,  0x4200802,  0x4200000,  0x200800,   0x0,        0x2,        0x4200802, 
						0x0,        0x200802,   0x4200000,  0x800,      0x4000002,  0x4000800,  0x800,      0x200002};

const int table5[64] = {0x80108020, 0x80008000, 0x8000,     0x108020,   0x100000,   0x20,       0x80100020, 0x80008020,
						0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x100000,   0x20,       0x80100020, 
						0x108000,   0x100020,   0x80008020, 0x0,        0x80000000, 0x8000,     0x108020,   0x80100000,
						0x100020,   0x80000020, 0x0,        0x108000,   0x8020,     0x80108000, 0x80100000, 0x8020, 
						0x0,        0x108020,   0x80100020, 0x100000,   0x80008020, 0x80100000, 0x80108000, 0x8000,
						0x80100000, 0x80008000, 0x20,       0x80108020, 0x108020,   0x20,       0x8000,     0x80000000, 
						0x8020,     0x80108000, 0x100000,   0x80000020, 0x100020,   0x80008020, 0x80000020, 0x100020, 
						0x108000,   0x0,        0x80008000, 0x8020,     0x80000000, 0x80100020, 0x80108020, 0x108000};

const int table6[64] = {0x802001,   0x2081,     0x2081,     0x80,       0x802080,   0x800081,   0x800001,   0x2001, 
						0x0,        0x802000,   0x802000,   0x802081,   0x81,       0x0,        0x800080,   0x800001,
						0x1,        0x2000,     0x800000,   0x802001,   0x80,       0x800000,   0x2001,     0x2080, 
						0x800081,   0x1,        0x2080,     0x800080,   0x2000,     0x802080,   0x802081,   0x81, 
						0x800080,   0x800001,   0x802000,   0x802081,   0x81,       0x0,        0x0,        0x802000, 
						0x2080,     0x800080,   0x800081,   0x1,        0x802001,   0x2081,     0x2081,     0x80, 
						0x802081,   0x81,       0x1,        0x2000,     0x800001,   0x2001,     0x802080,   0x800081, 
						0x2001,     0x2080,     0x800000,   0x802001,   0x80,       0x800000,   0x2000,     0x802080};

const int table7[64] = {0x20000010, 0x20400000, 0x4000,     0x20404010, 0x20400000, 0x10,       0x20404010, 0x400000, 
						0x20004000, 0x404010,   0x400000,   0x20000010, 0x400010,   0x20004000, 0x20000000, 0x4010, 
						0x0,        0x400010,   0x20004010, 0x4000,     0x404000,   0x20004010, 0x10,       0x20400010, 
						0x20400010, 0x0,        0x404010,   0x20404000, 0x4010,     0x404000,   0x20404000, 0x20000000,
						0x20004000, 0x10,       0x20400010, 0x404000,   0x20404010, 0x400000,   0x4010,     0x20000010,
						0x400000,   0x20004000, 0x20000000, 0x4010,     0x20000010, 0x20404010, 0x404000,   0x20400000, 
						0x404010,   0x20404000, 0x0,        0x20400010, 0x10,       0x4000,     0x20400000, 0x404010, 
						0x4000,     0x400010,   0x20004010, 0x0,        0x20404000, 0x20000000, 0x400010,   0x20004010};

const int table8[64] = {0x10001040, 0x1000,     0x40000,    0x10041040, 0x10000000, 0x10001040, 0x40,       0x10000000, 
						0x40040,    0x10040000, 0x10041040, 0x41000,    0x10041000, 0x41040,    0x1000,     0x40, 
						0x10040000, 0x10000040, 0x10001000, 0x1040,     0x41000,    0x40040,    0x10040040, 0x10041000,
						0x1040,     0x0,        0x0,        0x10040040, 0x10000040, 0x10001000, 0x41040,    0x40000,
						0x41040,    0x40000,    0x10041000, 0x1000,     0x40,       0x10040040, 0x1000,     0x41040,
						0x10001000, 0x40,       0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000,    0x10001040, 
						0x0,        0x10041040, 0x40040,    0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x0, 
						0x10041040, 0x41000,    0x41000,    0x1040,     0x1040,     0x40040,    0x10000000, 0x10041000};

// key 由字符串"liuan814"变换而来,作者的名字? 每次产生的key都是一样的.
const int g_key[8 * 4] ={0x3C3A2A09, 0x0A26082C, 0x3C381010, 0x0B263438,
					     0x38390224, 0x0B26130C, 0x38192802, 0x0F360534,
					     0x391D102A, 0x0D321027, 0x390D2522, 0x2D332019,
					     0x2B0D000D, 0x3D133115, 0x0B0F0406, 0x351B3A20,
					     0x0B0F0509, 0x3519060F, 0x07270D03, 0x35192900,
					     0x07272015, 0x36190A23, 0x07360B38, 0x360D2A00,
					     0x16361E15, 0x320D0412, 0x16320300, 0x1A2D1C0A,
					     0x34323111, 0x1A2E0700, 0x343A1620, 0x0A2E1911};

/*
const char g_base64[64] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
						   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
						   'g', 'h', 'i','j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
						   'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
						   */

BYTE g_rev_base64[TABLE_LEN] = {-1};
BOOL g_bInitBase64 = FALSE;

// base64转换用的表
void InitRevBase64Table()
{
	int i;

	if(g_bInitBase64)
	{
		return;
	}

	memset(g_rev_base64, -1, TABLE_LEN);

	for(i = 'A'; i <= 'Z'; i++)
	{
		g_rev_base64[i] = i - 'A';
	}

	for(i = 'a'; i <= 'z'; i++)
	{
		g_rev_base64[i] = i - 'a' + 26;
	}

	for(i = '0'; i <= '9'; i++)
	{
		g_rev_base64[i] = i - '0' + 52;
	}

	g_rev_base64['+'] = 62;
	g_rev_base64['/'] = 63;
	g_rev_base64['='] = -2;
}

int DecodeINodeP(char  *Base64Hash,			// base64 hash
				 size_t  HashLen,			// Base64Hash大小
				 char  *Password,			// 接受解密后的密码
				 size_t *PassSize)			// Password缓冲区大小
{
	char *pEncrypt;
	size_t i, j;
	char byte[4];

	if(!g_bInitBase64)
	{
		InitRevBase64Table();
	}

	if(HashLen <= 0 || HashLen % 4 != 0)
	{
		// base64编码长度错误
		return -1;
	}

	pEncrypt = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, HashLen / 4 * 3 + 1);
	if(pEncrypt == NULL)
	{
		return -1;
	}

	j = 0;
	i = 0;
	for(; i < HashLen - 4; i += 4)
	{
		byte[0] = g_rev_base64[Base64Hash[i]];
		byte[1] = g_rev_base64[Base64Hash[i + 1]];
		byte[2] = g_rev_base64[Base64Hash[i + 2]];
		byte[3] = g_rev_base64[Base64Hash[i + 3]];

		if(byte[0] < 0 || byte[1] < 0 || byte[2] < 0 || byte[3] < 0)
		{
			// 不是base64编码
			HeapFree(GetProcessHeap(), 0, pEncrypt);
			return -1;
		}

		pEncrypt[j++] = (byte[0] << 2) | ((byte[1] >> 4) & 3);
		pEncrypt[j++] = (byte[1] << 4) | ((byte[2] >> 2) & 0xf);
		pEncrypt[j++] = (byte[2] << 6) | (byte[3] & 0x3f);
	}
	// 剩余的4byte
	byte[0] = g_rev_base64[Base64Hash[i]];
	byte[1] = g_rev_base64[Base64Hash[i + 1]];
	byte[2] = g_rev_base64[Base64Hash[i + 2]];
	byte[3] = g_rev_base64[Base64Hash[i + 3]];
	pEncrypt[j++] = (byte[0] << 2) | ((byte[1] >> 4) & 3);
	if(Base64Hash[i + 2] != '=')
	{
		pEncrypt[j++] = (byte[1] << 4) | ((byte[2] >> 2) & 0xf);
		if(Base64Hash[i + 3] != '=')
		{
			pEncrypt[j++] = (byte[2] << 6) | (byte[3] & 0x3f);
		}
	}
	// Encrypt的长度为8的倍数,参看下边password的布局.
	if(j % 8 != 0)
	{
		HeapFree(GetProcessHeap(), 0, pEncrypt);
		return -1;
	}
	
	// 继续解密
	i = 0;
	while(i < j)
	{
		DecodePhase1((int *)&pEncrypt[i], &pEncrypt[i]);
		i += 8;
	}

	// 验证密码布局
	if(pEncrypt[j - 1] < 8)
	{
		// 'password'[8 - strlen(password)%8...] 
		for(i = j - pEncrypt[j - 1]; i < j; i++)
		{
			if(pEncrypt[i] != pEncrypt[j - 1])
			{
				HeapFree(GetProcessHeap(), 0, pEncrypt);
				return -1;
			}
		}
		j -= pEncrypt[j - 1]; // 修正密码长度
		pEncrypt[j] = '\0';
	}

	if(*PassSize > j)
	{
		RtlCopyMemory(Password, pEncrypt, j);
		Password[j] = '\0';
		*PassSize = j + 1;
		HeapFree(GetProcessHeap(), 0, pEncrypt);
		return 0;
	}
	else
	{
		*PassSize = j + 1;
		HeapFree(GetProcessHeap(), 0, pEncrypt);
		return 1;
	}
}

/*
第一阶段逆序
.text:10010310                 sub     esp, 8
.text:10010313                 mov     eax, [esp+8+password]
.text:10010317                 movzx   edx, byte ptr [eax+2]
.text:1001031B                 xor     ecx, ecx
.text:1001031D                 mov     ch, [eax]
.text:1001031F                 push    edi
.text:10010320                 lea     edi, [esp+0Ch+code1]				// 下边的encrypt_code1
.text:10010324                 mov     cl, [eax+1]
.text:10010327                 shl     ecx, 8
.text:1001032A                 or      ecx, edx
.text:1001032C                 movzx   edx, byte ptr [eax+3]
.text:10010330                 shl     ecx, 8
.text:10010333                 or      ecx, edx
.text:10010335                 movzx   edx, byte ptr [eax+6]
.text:10010339                 mov     [esp+0Ch+code1], ecx
.text:1001033D                 xor     ecx, ecx
.text:1001033F                 mov     ch, [eax+4]
.text:10010342                 mov     cl, [eax+5]
.text:10010345                 movzx   eax, byte ptr [eax+7]
.text:10010349                 shl     ecx, 8
.text:1001034C                 or      ecx, edx
.text:1001034E                 mov     edx, [esp+0Ch+key]
.text:10010352                 shl     ecx, 8
.text:10010355                 or      ecx, eax
.text:10010357                 mov     [esp+0Ch+code2], ecx				// 下边的encrypt_code2

 password 布局为 'password'[8 - strlen(password)%8...] ,每次有8个byte,多于8的下次再加密,少于8的按上述布局补充
	例如"123456"布局为34333231 [0202]3536, "12345"布局为34333231 [030303]35
code1 = (password[0] << 24) | (password[1] << 16) | (password[2] << 8) | password[3];
code2 = (password[4] << 24) | (password[5] << 16) | (password[6] << 8) | password[7];

接着对逆序结果加密.code1加密为encrypt_code1, code2加密为encrypt_code2
.text:1001035B                 call    sub_10010110

第二阶段逆序
text:10010360                 mov     ecx, [esp+0Ch+encrypt_code1]
.text:10010364                 mov     eax, [esp+0Ch+encrypt_addr]
.text:10010368                 mov     edx, ecx
.text:1001036A                 shr     edx, 18h
.text:1001036D                 mov     [eax], dl
.text:1001036F                 mov     edx, ecx
.text:10010371                 shr     edx, 10h
.text:10010374                 mov     [eax+1], dl
.text:10010377                 mov     edx, ecx
.text:10010379                 shr     edx, 8
.text:1001037C                 mov     [eax+2], dl
.text:1001037F                 mov     [eax+3], cl
.text:10010382                 mov     ecx, [esp+0Ch+encrypt_code2]
.text:10010386                 mov     edx, ecx
.text:10010388                 shr     edx, 18h
.text:1001038B                 mov     [eax+4], dl
.text:1001038E                 mov     edx, ecx
.text:10010390                 shr     edx, 10h
.text:10010393                 mov     [eax+5], dl
.text:10010396                 mov     edx, ecx
.text:10010398                 shr     edx, 8
.text:1001039B                 mov     [eax+6], dl
.text:1001039E                 mov     [eax+7], cl

encrypt_addr[0] = (encrypt_code1 >> 24) | ((encrypt_code1 >> 16) & 0xff) | ((encrypt_code1 >> 8) & 0xff) | (encrypt_code1 & 0xff)
encrypt_addr[1] = (encrypt_code2 >> 24) | ((encrypt_code2 >> 16) & 0xff) | ((encrypt_code2 >> 8) & 0xff) | (encrypt_code2 & 0xff)
*/
// 字节逆序还原
void DecodePhase1(int  EncryptAddress[2],	// 加密后的两个int
				  char  Password[8])		// 解密后的两个int, 8 byte
{
	int EncryptCode[2];

	// 先对第二次逆序还原
	EncryptCode[0] = ((EncryptAddress[0] & 0xff) << 24) |  ((EncryptAddress[0] & 0xff00) << 8) | \
						((EncryptAddress[0] & 0xff0000) >> 8) | ((EncryptAddress [0] & 0xff000000) >> 24);
	EncryptCode[1] = ((EncryptAddress[1] & 0xff) << 24) |  ((EncryptAddress[1] & 0xff00) << 8) | \
						((EncryptAddress[1] & 0xff0000) >> 8) | ((EncryptAddress [1] & 0xff000000) >> 24);
	
	DecodePhase2(EncryptCode);

	// 第一次逆序还原
	Password[0] = (EncryptCode[0] & 0xff000000) >> 24;
	Password[1] = (EncryptCode[0] & 0xff0000) >> 16;
	Password[2] = (EncryptCode[0] & 0xff00) >> 8;
	Password[3] = EncryptCode[0] & 0xff;
	Password[4] = (EncryptCode[1] & 0xff000000) >> 24;
	Password[5] = (EncryptCode[1] & 0xff0000) >> 16;
	Password[6] = (EncryptCode[1] & 0xff00) >> 8;
	Password[7] = EncryptCode[1] & 0xff;
}

// sub_10010110加密还原, sub_10010110一次只加密两个int,且加密结果也为两个int
void DecodePhase2(int  code[2])
{
	int i;
	int t3, t1;
	int vs61, vs62;

#pragma warning(disable:4102)
	/* encode step12:
	* code[0] = vs121, code[1] = vs122
	*vs121 = ((vs112 << 4) & f0f0f0f0) | (vs111 & 0f0f0f0f)
	*vs122 = ((vs111 >> 4) & 0f0f0f0f) | (vs112 & f0f0f0f0)
	* test:vs121 = E1519E0B, vs122 = 3E26CD9D
	*      vs111 = E161DEDB, vs112 = 3E25C990
	*/
	// decode step1
LDecodeStep1_12:
	code[0] ^= ((code[1] & 0x0f0f0f0f) << 4);
	code[1] ^= ((code[0] & 0xf0f0f0f0) >> 4);			// code[1] = vs112
	code[0] ^= ((code[1] & 0x0f0f0f0f) << 4);			// code[0] = vs111


	/* encode step11:
	* code[0] = vs111, code[1] = vs112
	* vs111 = ((vs101 << 16) & ffff0000) | (vs102 & ffff)
	* vs112 = ((vs102 >> 16) & ffff) | (vs101 & ffff0000)
	* test:vs111 = E161DEDB, vs112 = 3E25C990
	*      vs101 = 3E25E161, vs102 = C990DEDB
	*/
	// decode step2
LDecodeStep2_11:
	code[0] ^= ((code[1] & 0xffff) << 16);
	code[1] ^= ((code[0] & 0xffff0000) >> 16);			// code[1] = vs101
	code[0] ^= ((code[1] & 0xffff) << 16);				// code[0] = vs102


	/* encode step10:
	* code[1] = vs101, code[0] = vs102
	* vs101 = ((vs92 << 2) & cccccccc) | (vs91 & 33333333)
	* vs102 = (vs92 & cccccccc) | ((vs91 >> 2) & 33333333)
	* test vs101 = 3E25E161, vs102 = C990DEDB
	*	   vs91 = 3661696D, vs92 = CB81FCD8
	*/
	// decode step3
LDecodeStep3_10:
	code[1] ^= ((code[0] & 0x33333333) << 2);
	code[0] ^= ((code[1] & 0xcccccccc) >> 2);			// code[0] = vs92
	code[1] ^= ((code[0] & 0x33333333) << 2);			// code[1] = vs91


	/* encode step9
	* code[1] = vs91, code[0] = vs92
	* vs91 = ((vs82 << 8) & ff00ff00) | ((vs81 ror 1) & ff00ff)
	* vs92 = (vs82 & ff00ff00) | ((vs81 ror 1) >> 8 & ff00ff)
	* test vs91 = 3661696D, vs92 = CB81FCD8
	*	   vs81 = 02C3B0DB, vs82 = CB36FC69
	*/
LDecodeStep4_9:
	code[1] ^= (code[0] & 0xff00ff) << 8;
	code[0] ^= ((code[1] & 0xff00ff00) >> 8);			// code[0] = vs82
	code[1] ^= (code[0] & 0xff00ff) << 8;				// code[1] = (vs81 ror 1)
	__asm mov eax, code
	__asm rol dword ptr [eax + 4], 1					// code[1] = vs81


	/* encode step8
	* code[1] = vs81, code[0] = vs82
	* vs81 = ((vs72 ror 1) & AAAAAAAA) | (vs71 & 55555555)
	* vs82 = (vs71 & AAAAAAAA) | ((vs72 ror 1) & 55555555)
	* test vs81 = 02C3B0DB, vs82 = CB36FC69
	*      vs71 = 8A63B879, vs72 = 872DE996
	*/
LDecodeStep5_8:
	code[1] ^= (code[0] & 0xaaaaaaaa);
	code[0] ^= (code[1] & 0xaaaaaaaa);					// code[0] = vs72 ror 1
	code[1] ^= (code[0] & 0xaaaaaaaa);					// code[1] = vs71
	__asm mov eax, dword ptr [code]
	__asm rol dword ptr [eax], 1						// code[0] = vs72


	/* encode step7,
	* code[1] = vs71, code[0] = vs72, arg2 = key
	* Loop step:
	*/
LDecodeStep6_7:
	vs61 = code[1];
	vs62 = code[0];
L1_4:
	for(i = 8 * 4 - 1; i >= 0;)
	{
		/*
		* L4:
		* t1 = *arg2++;
		* t1 ^= vs61;
		* t3 = AT5[t1 >> 24 & 3f];
		* t3 ^= AT6[t1 >> 16 & 3f];
		* t3 ^= AT7[t1 >> 8 & 3f];
		* t3 ^= AT8[t1 & 3f];
		* vs62 ^= t3
		*/
		t1 = g_key[i--];
		t1 ^= vs61;
		t3 = table5[(t1 >> 24) & 0x3f];
		t3 ^= table6[(t1 >> 16) & 0x3f];
		t3 ^= table7[(t1 >> 8) & 0x3f];
		t3 ^= table8[t1 & 0x3f];
		vs62 ^= t3;

		/*
		* L3:
		* t1 = vs61;
		* ror t1 4;
		* t1 ^= *arg2++;
		* t3 = AT1[t1 >> 24 & 3f];
		* t3 ^= AT2[t1 >> 16 & 3f];
		* t3 ^= AT3[t1 >> 8 & 3f];
		* t3 ^= AT4[t1 & 3f];
		* vs62 ^= t3;
		*/
		t1 = vs61;
		__asm ror dword ptr [t1], 4
		t1 ^= g_key[i--];
		t3 = table1[(t1 >> 24) & 0x3f];
		t3 ^= table2[(t1 >> 16) & 0x3f];
		t3 ^= table3[(t1 >> 8) & 0x3f];
		t3 ^= table4[t1 & 0x3f];
		vs62 ^= t3;

		/*
		* L2:
		* t1 = *arg2++;
		* t1 ^= vs62;
		* t3 = AT5[t1 >> 24 & 3f];
		* t3 ^= AT6[t1 >> 16 & 3f];
		* t3 ^= AT7[t1 >> 8 & 3f];
		* t3 ^= AT8[t1 & 3f];
		* vs61 ^= t3;
		*/
		t1 = g_key[i--];
		t1 ^= vs62;
		t3 = table5[(t1 >> 24) & 0x3f];
		t3 ^= table6[(t1 >> 16) & 0x3f];
		t3 ^= table7[(t1 >> 8) & 0x3f];
		t3 ^= table8[t1 & 0x3f];
		vs61 ^= t3;

		/*L1
		* t1 = vs62;
		* ror t1 4;
		* t1 ^= *arg2++;
		* t3 = AT1[t1 >> 24 & 3f];
		* t3 ^= AT2[t1 >> 16 & 3f];
		* t3 ^= AT3[t1 >> 8 & 3f];
		* t3 ^= AT4[t1 & 3f];
		* vs61 ^= t3;
		*/
		t1 = vs62;
		__asm ror dword ptr [t1], 4
		t1 ^= g_key[i--];
		t3 = table1[(t1 >> 24) & 0x3f];
		t3 ^= table2[(t1 >> 16) & 0x3f];
		t3 ^= table3[(t1 >> 8) & 0x3f];
		t3 ^= table4[t1 & 0x3f];
		vs61 ^= t3;
		__asm nop
	}

	code[0] = vs62;
	code[1] = vs61;

	//code[0] = 0x007E01CC; code[1] = 0x007E702A;


	/* encode step6
	* code[0] = vs62, code[1] = vs61
	* vs61 = ((vs51 rol 1) & aaaaaaaa) | (vs52 & 55555555)
	* vs62 = (vs52 & aaaaaaaa) | ((vs51 rol 1) & 55555555)
	* rol vs 61 1
	* test vs51 = 003F14A2, vs52 = 003F109D
	*      vs61 = 007E702A, vs62 = 007E01CC
	*/
LDecodeStep7_6:
	__asm mov eax, dword ptr [code]
	__asm ror dword ptr [eax + 4], 1					// vs61 ror 1
	code[1] ^= (code[0] & 0xaaaaaaaa);
	code[0] ^= (code[1] & 0xaaaaaaaa);					// code[0] = vs51 rol 1
	code[1] ^= (code[0] & 0xaaaaaaaa);					// code[1] = vs52
	__asm mov eax, dword ptr [code]
	__asm ror dword ptr [eax], 1						// code[0] = vs51


	/* encode step5
	* code[0] = vs51, code[1] = vs52
	* vs51 = (vs41 && ff00ff) | (vs42 << 8) &ff00ff00
	* vs52 = ((vs41 >> 8) & ff00ff) | (vs42 & ff00ff00)
	* test vs41 = 3F3F9DA2, vs42 = 00001014
	*      vs51 = 003F14A2, vs52 = 003F109D
	*/
LDecodeStep8_5:
	code[0] ^= ((code[1] & 0xff00ff) << 8);
	code[1] ^= ((code[0] & 0xff00ff00) >> 8);			// code[1] = vs42
	code[0] ^= ((code[1] & 0xff00ff) << 8);				// code[0] = vs41


	/* encode step4
	* code[0] = vs41, code[1] = vs42
	* vs41 = ((vs32 << 2) & cccccccc) | (vs31 & 33333333)
	* vs42 = (vs32 & cccccccc) | ((vs31 >> 2) & 33333333)
	* test vs31 = 33335162, vs32 = 03032324
	*      vs41 = 3F3F9DA2, vs42 = 00001014
	*/
LDecodeStep9_4:
	code[0] ^= ((code[1] & 0x33333333) << 2);
	code[1] ^= ((code[0] & 0xcccccccc) >> 2);			// code[1] = vs32
	code[0] ^= ((code[1] & 0x33333333) << 2);			// code[0] = vs31


	/* encode step3
	* code[0] = vs31, code[1] = vs32
	* vs1低16位与vs2高16位互换
	* code[0] = ((vs1 << 16) & 0xffff0000) | (vs2 & 0xffff)
	* code[1] = ((vs2 >> 16) & 0xffff) | (vs1 & 0xffff0000)
	* test vs1 = 33330303, vs2 = 51622324
	*      vs31 = 33335162, vs32 = 03032324
	*/
LDecodeStep10_3:
	code[0] ^= ((code[1] & 0xffff0000) >> 16);
	code[1] ^= ((code[0] & 0xffff) << 16);				// code[1] = vs2
	code[0] ^= ((code[1] & 0xffff0000) >> 16);			// code[0] = vs1


	/* encode step2, 1
	* code[0] = vs1, code[0] = vs1
	* vs1 = ((a >> 4) & 0f0f0f0f) | (b & f0f0f0f0);
	* vs2 = ((b << 4) & f0f0f0f0) | (a & 0f0f0f0f);
	* test a = 31323334, b = 35360202,
	*      vs1 = 33330303, vs2 = 51622324
	*/
LDecodeStep11_2_1:
	code[0] ^= ((code[1] & 0xf0f0f0f0) >> 4);
	code[1] ^= ((code[0] & 0x0f0f0f0f) << 4);			// code[1] = a
	code[0] ^= ((code[1] & 0xf0f0f0f0) >> 4);			// code[0] = b

	code[0] ^= code[1];
	code[1] ^= code[0];			// code[1] = b
	code[0] ^= code[1];			// code[0] = a
}