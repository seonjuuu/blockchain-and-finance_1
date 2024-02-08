#include <stdio.h>
#include <inttypes.h>
#include <string.h>

//
#define AES128
#ifdef AES128
int Nr = 10;   //number round
int Nb = 16;   //number bytes
int Nw = 4;    //number words
#endif


uint8_t Rkey[11][16];

static const uint8_t sbox[256] = {
	//i     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

void PrintRKey()
{
	for (int i = 1; i < Nr + 1; i++)
	{
		printf("Round %d key  :: ", i);
		for (int j = 0; j < Nb; j++)
		{
			printf("%02x ", Rkey[i][j]);
		}
		printf("\n");
	}
}

void RoundkeyGen()
{
	for (int i = 1; i < Nr + 1; i++)
	{
		//step1 : rotate
		// == ith ==  => = i+1 th =
		// 0 4 8 (12) =>  (0/13)        // i th �� �� 13�� i+1 th �� ���� 0�� �ڸ���
		// 1 5 9 (13)     (1/14)
		// 2 6 10 (14)    (2/15)
		// 3 7 11 (15)    (3/12)
		Rkey[i][0] = Rkey[i - 1][13];
		Rkey[i][1] = Rkey[i - 1][14];
		Rkey[i][2] = Rkey[i - 1][15];
		Rkey[i][3] = Rkey[i - 1][12];



		//step2 : subbyte
		Rkey[i][0] = sbox[Rkey[i][0]];
		Rkey[i][1] = sbox[Rkey[i][1]];
		Rkey[i][2] = sbox[Rkey[i][2]];
		Rkey[i][3] = sbox[Rkey[i][3]];


		//step3 : XOR
		Rkey[i][0] = Rkey[i][0] ^ Rkey[i - 1][0] ^ Rcon[i];
		Rkey[i][1] = Rkey[i][1] ^ Rkey[i - 1][1];
		Rkey[i][2] = Rkey[i][2] ^ Rkey[i - 1][2];
		Rkey[i][3] = Rkey[i][3] ^ Rkey[i - 1][3];

		//step4 :
		Rkey[i][4] = Rkey[i][0] ^ Rkey[i - 1][4];
		Rkey[i][5] = Rkey[i][1] ^ Rkey[i - 1][5];
		Rkey[i][6] = Rkey[i][2] ^ Rkey[i - 1][6];
		Rkey[i][7] = Rkey[i][3] ^ Rkey[i - 1][7];

		Rkey[i][8] = Rkey[i][4] ^ Rkey[i - 1][8];
		Rkey[i][9] = Rkey[i][5] ^ Rkey[i - 1][9];
		Rkey[i][10] = Rkey[i][6] ^ Rkey[i - 1][10];
		Rkey[i][11] = Rkey[i][7] ^ Rkey[i - 1][11];

		Rkey[i][12] = Rkey[i][8] ^ Rkey[i - 1][12];
		Rkey[i][13] = Rkey[i][9] ^ Rkey[i - 1][13];
		Rkey[i][14] = Rkey[i][10] ^ Rkey[i - 1][14];
		Rkey[i][15] = Rkey[i][11] ^ Rkey[i - 1][15];
	}
	//print one round key
}


void PrintValue(uint8_t* ct)
{
	for (int j = 0; j < Nb; j++)
	{
		printf("%02x ", ct[j]);
	}
	printf("\n");
}

// Inverse Mc

uint8_t InverseMc(uint8_t a, uint8_t x)
{
	uint8_t res = 0;

	res ^= (x & 1) * a;          // a*1  //x�� 1�̸� = (x&1)
	res ^= ((x >> 1) & 1) * ((((a >> 7) & 1) * 0x1b) ^ (a << 1));  //a*x
	res ^= ((x >> 2) & 1) * ((((a >> 6) & 1) * 0x1b) ^ (((a >> 7) & 1) * 0x36) ^ (a << 2));  //a*x^1
	res ^= ((x >> 3) & 1) * ((((a >> 5) & 1) * 0x1b) ^ (((a >> 6) & 1) * 0x36) ^ (((a >> 7) & 1) * 0x6c) ^ (a << 3)); //a*x^2
	return res;
}


void AES_enc(uint8_t* ct, uint8_t* pt)
{
	uint32_t w[4] = { 0, };
	uint8_t t0, t1, t2, t3, t4, t5, t6, t7;

	// 0Round ct<-pt^Key
	for (int i = 0; i < Nb; i++)
	{
		ct[i] = pt[i] ^ Rkey[0][i];                  // key[i] -> Rkey[0][i] , key�� ���������� �ƴϹǷ� mempy�� ���� Rkey[0]�� ������Ű�� �����س����� �̿�
	}
	//printf("== 0 round == \n");
	//PrintValue(ct);

	// 1Round ~ Last round-1
	for (int nrnd = 0; nrnd < Nr - 1; nrnd++)
	{
		//subbyte
		for (int j = 0; j < Nb; j++)
		{
			ct[j] = sbox[ct[j]];
		}

		//shiftrow
		//byte-to-word
		// w[0] =ct[0] ct[4] ct[8] ct[12]
		for (int j = 0; j < Nw; j++)
		{
			w[j] = (ct[j] << 24) ^ (ct[4 + j] << 16) ^ (ct[8 + j] << 8) ^ (ct[12 + j]);
		}
		for (int j = 0; j < Nw; j++)
		{
			printf("w[%d]:%x \n", j, w[j]);
		}

		//rotate
		w[1] = (w[1] << 8) ^ ((w[1] & 0xff000000) >> 24);
		w[2] = (w[2] << 16) ^ ((w[2] & 0xffff0000) >> 16);
		w[3] = (w[3] << 24) ^ ((w[3] & 0xffffff00) >> 8);


		//32bit�� 8bit��
		for (int j = 0; j < Nw; j++)
		{
			ct[j] = ((w[j] & 0xff000000) >> 24) & 0xff;               //0xff000000 = shift �ϸ� �տ� �͵��� ������� ������ �̸� ���� ������� �κ��� ���� (&=XOR)
			ct[4 + j] = ((w[j] & 0x00ff0000) >> 16) & 0xff;
			ct[8 + j] = ((w[j] & 0x0000ff00) >> 8) & 0xff;
			ct[12 + j] = ((w[j] & 0x000000ff)) & 0xff;
		}
		//PrintValue(ct);


		//mixcolum
		//ct[0], ct[1], ct[2], ct[3]
		//ct[0]*02(=x)
		t0 = (((ct[0] >> 7) & 1) * 0x1b) ^ (ct[0] << 1);
		//ct[1]*03(=x+1)
		t1 = (((ct[1] >> 7) & 1) * 0x1b) ^ (ct[1] << 1) ^ ct[1];         // �� �������� �ڽ��ڽ��� �ѹ� �� �����ָ� �� 
		t0 = t0 ^ t1 ^ ct[2] ^ ct[3]; //new ct[0]

		t2 = (((ct[1] >> 7) & 1) * 0x1b) ^ (ct[1] << 1);
		t3 = (((ct[2] >> 7) & 1) * 0x1b) ^ (ct[2] << 1) ^ ct[2];
		t3 = ct[0] ^ t2 ^ t3 ^ ct[3];

		t4 = (((ct[2] >> 7) & 1) * 0x1b) ^ (ct[2] << 1);
		t5 = (((ct[3] >> 7) & 1) * 0x1b) ^ (ct[3] << 1) ^ ct[3];
		t5 = ct[0] ^ ct[1] ^ t4 ^ t5;

		t6 = (((ct[0] >> 7) & 1) * 0x1b) ^ (ct[0] << 1) ^ ct[0];
		t7 = (((ct[3] >> 7) & 1) * 0x1b) ^ (ct[3] << 1);
		t7 = t6 ^ ct[1] ^ ct[2] ^ t7;

		ct[0] = t0;
		ct[1] = t3;
		ct[2] = t5;
		ct[3] = t7;

		//2nd cloumn
		// 0->4, 1->5, 2->6, 3->7 
		t0 = (((ct[4] >> 7) & 1) * 0x1b) ^ (ct[4] << 1);
		t1 = (((ct[5] >> 7) & 1) * 0x1b) ^ (ct[5] << 1) ^ ct[5];
		t0 = t0 ^ t1 ^ ct[6] ^ ct[7]; //new ct[4]

		t2 = (((ct[5] >> 7) & 1) * 0x1b) ^ (ct[5] << 1);
		t3 = (((ct[6] >> 7) & 1) * 0x1b) ^ (ct[6] << 1) ^ ct[6];
		t3 = ct[4] ^ t2 ^ t3 ^ ct[7];

		t4 = (((ct[6] >> 7) & 1) * 0x1b) ^ (ct[6] << 1);
		t5 = (((ct[7] >> 7) & 1) * 0x1b) ^ (ct[7] << 1) ^ ct[7];
		t5 = ct[4] ^ ct[5] ^ t4 ^ t5;

		t6 = (((ct[4] >> 7) & 1) * 0x1b) ^ (ct[4] << 1) ^ ct[4];
		t7 = (((ct[7] >> 7) & 1) * 0x1b) ^ (ct[7] << 1);
		t7 = t6 ^ ct[5] ^ ct[6] ^ t7;

		ct[4] = t0;
		ct[5] = t3;
		ct[6] = t5;
		ct[7] = t7;

		//
		t0 = (((ct[8] >> 7) & 1) * 0x1b) ^ (ct[8] << 1);
		t1 = (((ct[9] >> 7) & 1) * 0x1b) ^ (ct[9] << 1) ^ ct[9];
		t0 = t0 ^ t1 ^ ct[10] ^ ct[11]; //new ct[4]

		t2 = (((ct[9] >> 7) & 1) * 0x1b) ^ (ct[9] << 1);
		t3 = (((ct[10] >> 7) & 1) * 0x1b) ^ (ct[10] << 1) ^ ct[10];
		t3 = ct[8] ^ t2 ^ t3 ^ ct[11];

		t4 = (((ct[10] >> 7) & 1) * 0x1b) ^ (ct[10] << 1);
		t5 = (((ct[11] >> 7) & 1) * 0x1b) ^ (ct[11] << 1) ^ ct[11];
		t5 = ct[8] ^ ct[9] ^ t4 ^ t5;

		t6 = (((ct[8] >> 7) & 1) * 0x1b) ^ (ct[8] << 1) ^ ct[8];
		t7 = (((ct[11] >> 7) & 1) * 0x1b) ^ (ct[11] << 1);
		t7 = t6 ^ ct[9] ^ ct[10] ^ t7;

		ct[8] = t0;
		ct[9] = t3;
		ct[10] = t5;
		ct[11] = t7;

		//
		t0 = (((ct[12] >> 7) & 1) * 0x1b) ^ (ct[12] << 1);
		t1 = (((ct[13] >> 7) & 1) * 0x1b) ^ (ct[13] << 1) ^ ct[13];
		t0 = t0 ^ t1 ^ ct[14] ^ ct[15]; //new ct[0]

		t2 = (((ct[13] >> 7) & 1) * 0x1b) ^ (ct[13] << 1);
		t3 = (((ct[14] >> 7) & 1) * 0x1b) ^ (ct[14] << 1) ^ ct[14];
		t3 = ct[12] ^ t2 ^ t3 ^ ct[15];

		t4 = (((ct[14] >> 7) & 1) * 0x1b) ^ (ct[14] << 1);
		t5 = (((ct[15] >> 7) & 1) * 0x1b) ^ (ct[15] << 1) ^ ct[15];
		t5 = ct[12] ^ ct[13] ^ t4 ^ t5;

		t6 = (((ct[12] >> 7) & 1) * 0x1b) ^ (ct[12] << 1) ^ ct[12];
		t7 = (((ct[15] >> 7) & 1) * 0x1b) ^ (ct[15] << 1);
		t7 = t6 ^ ct[13] ^ ct[14] ^ t7;

		ct[12] = t0;
		ct[13] = t3;
		ct[14] = t5;
		ct[15] = t7;

		//printf("mix colum:");
		//PrintValue(ct);


		//addroundkey
		for (int i = 0; i < Nb; i++)
		{
			ct[i] = ct[i] ^ Rkey[nrnd + 1][i];
		}

	} // Nr-1

	printf("After ninthround :");
	PrintValue(ct);

	// Nr 
	//subbyte
	for (int j = 0; j < Nb; j++)
	{
		ct[j] = sbox[ct[j]];
	}

	//shiftrow
	//byte-to-word
	// w[0] =ct[0] ct[4] ct[8] ct[12]
	for (int j = 0; j < Nw; j++)
	{
		w[j] = (ct[j] << 24) ^ (ct[4 + j] << 16) ^ (ct[8 + j] << 8) ^ (ct[12 + j]);
	}
	for (int j = 0; j < Nw; j++)
	{
		printf("w[%d]:%x \n", j, w[j]);
	}

	//rotate
	w[1] = (w[1] << 8) ^ ((w[1] & 0xff000000) >> 24);
	w[2] = (w[2] << 16) ^ ((w[2] & 0xffff0000) >> 16);
	w[3] = (w[3] << 24) ^ ((w[3] & 0xffffff00) >> 8);


	//32bit�� 8bit��
	for (int j = 0; j < Nw; j++)
	{
		ct[j] = ((w[j] & 0xff000000) >> 24) & 0xff;               //0xff000000 = shift �ϸ� �տ� �͵��� ������� ������ �̸� ���� ������� �κ��� ���� (&=XOR)
		ct[4 + j] = ((w[j] & 0x00ff0000) >> 16) & 0xff;
		ct[8 + j] = ((w[j] & 0x0000ff00) >> 8) & 0xff;
		ct[12 + j] = ((w[j] & 0x000000ff)) & 0xff;
	}

	//addround
	for (int i = 0; i < Nb; i++)
	{
		ct[i] = ct[i] ^ Rkey[Nr][i];
	}

	printf("cipertext :");
	PrintValue(ct);

}


void main()
{

	uint8_t Key[16] = {0,};//{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t  pt[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	unsigned char ct[16] = { 0, };
	uint8_t cttmp[16] = { 0 }; // ���ο� ���� . ct ��ȣȭ ����
	uint32_t w[4] = { 0, };
	uint8_t t0, t1, t2, t3, t4, t5, t6, t7;

	//Rkey 0 = >master key<
	//Rkey 1 => Round 1
	//Rkey 2 => Round 2

	memcpy(Rkey[0], Key, sizeof(Key));

	RoundkeyGen();

	PrintRKey();

	//PrintValue(Key);

	AES_enc(ct, pt);            // �� �޾Ƽ� ��ȣ�� ����ϴ� �Լ�


	ct[0] = 0xee;
	ct[1] = 0xa8;
	ct[2] = 0x8e;
	ct[3] = 0x8b;
	ct[4] = 0x56;
	ct[5] = 0x0f;
	ct[6] = 0x44;
	ct[7] = 0xa6;
	ct[8] = 0xce;
	ct[9] = 0x38;
	ct[10] = 0xc2;
	ct[11] = 0x04;
	ct[12] = 0xc1;
	ct[13] = 0x8b;
	ct[14] = 0x3c;
	ct[15] = 0x87;


	//��ȣȭ
	// 
	//addroundkey
	for (int i = 0; i < Nb; i++)
	{
		cttmp[i] = ct[i] ^ Rkey[Nr][i];
	}

	printf("DES = add round key:");
	PrintValue(cttmp);


	for (int nrnd = 0; nrnd < Nr - 1; nrnd++)
	{
		// inverse shift row
		// w[0] =ct[0] ct[4] ct[8] ct[12]
		// ��ȭX
		for (int j = 0; j < Nw; j++)
		{
			w[j] = (cttmp[j] << 24) ^ (cttmp[4 + j] << 16) ^ (cttmp[8 + j] << 8) ^ (cttmp[12 + j]);
		}
		for (int j = 0; j < Nw; j++)
		{
			printf("w[%d]:%x \n", j, w[j]);
		}

		//rotate (�̺κи� ��ȭ)
		w[1] = (w[1] >> 8) ^ ((w[1] & 0x000000ff) << 24);
		w[2] = (w[2] >> 16) ^ ((w[2] & 0x0000ffff) << 16);
		w[3] = (w[3] >> 24) ^ ((w[3] & 0x00ffffff) << 8);


		//32bit�� 8bit��(��ȭX)
		for (int j = 0; j < Nw; j++)
		{
			cttmp[j] = ((w[j] & 0xff000000) >> 24) & 0xff;
			cttmp[4 + j] = ((w[j] & 0x00ff0000) >> 16) & 0xff;
			cttmp[8 + j] = ((w[j] & 0x0000ff00) >> 8) & 0xff;
			cttmp[12 + j] = ((w[j] & 0x000000ff)) & 0xff;
		}
		printf("DES = Inverse sr:");
		PrintValue(cttmp);

		//subbyte
		for (int j = 0; j < Nb; j++)
		{
			cttmp[j] = rsbox[cttmp[j]];
		}

		//addroundkey
		for (int i = 0; i < Nb; i++)
		{
			cttmp[i] = cttmp[i] ^ Rkey[Nr - 1 - nrnd][i];  //nrndf�� �̿��Ͽ� round key�� �ϳ��� ����
		}
		printf("DES = Add round:");
		PrintValue(cttmp);


		//inverse mixcolumn
		t0 = InverseMc(cttmp[0], 0x0e);
		t0 ^= InverseMc(cttmp[1], 0x0b);
		t0 ^= InverseMc(cttmp[2], 0x0d);
		t0 ^= InverseMc(cttmp[3], 0x09);

		t3 = InverseMc(cttmp[0], 0x09);
		t3 ^= InverseMc(cttmp[1], 0x0e);
		t3 ^= InverseMc(cttmp[2], 0x0b);
		t3 ^= InverseMc(cttmp[3], 0x0d);

		t5 = InverseMc(cttmp[0], 0x0d);
		t5 ^= InverseMc(cttmp[1], 0x09);
		t5 ^= InverseMc(cttmp[2], 0x0e);
		t5 ^= InverseMc(cttmp[3], 0x0b);

		t7 = InverseMc(cttmp[0], 0x0b);
		t7 ^= InverseMc(cttmp[1], 0x0d);
		t7 ^= InverseMc(cttmp[2], 0x09);
		t7 ^= InverseMc(cttmp[3], 0x0e);

		cttmp[0] = t0;
		cttmp[1] = t3;
		cttmp[2] = t5;
		cttmp[3] = t7;


		t0 = InverseMc(cttmp[4], 0x0e);
		t0 ^= InverseMc(cttmp[5], 0x0b);
		t0 ^= InverseMc(cttmp[6], 0x0d);
		t0 ^= InverseMc(cttmp[7], 0x09);

		t3 = InverseMc(cttmp[4], 0x09);
		t3 ^= InverseMc(cttmp[5], 0x0e);
		t3 ^= InverseMc(cttmp[6], 0x0b);
		t3 ^= InverseMc(cttmp[7], 0x0d);

		t5 = InverseMc(cttmp[4], 0x0d);
		t5 ^= InverseMc(cttmp[5], 0x09);
		t5 ^= InverseMc(cttmp[6], 0x0e);
		t5 ^= InverseMc(cttmp[7], 0x0b);

		t7 = InverseMc(cttmp[4], 0x0b);
		t7 ^= InverseMc(cttmp[5], 0x0d);
		t7 ^= InverseMc(cttmp[6], 0x09);
		t7 ^= InverseMc(cttmp[7], 0x0e);

		cttmp[4] = t0;
		cttmp[5] = t3;
		cttmp[6] = t5;
		cttmp[7] = t7;

		t0 = InverseMc(cttmp[8], 0x0e);
		t0 ^= InverseMc(cttmp[9], 0x0b);
		t0 ^= InverseMc(cttmp[10], 0x0d);
		t0 ^= InverseMc(cttmp[11], 0x09);

		t3 = InverseMc(cttmp[8], 0x09);
		t3 ^= InverseMc(cttmp[9], 0x0e);
		t3 ^= InverseMc(cttmp[10], 0x0b);
		t3 ^= InverseMc(cttmp[11], 0x0d);

		t5 = InverseMc(cttmp[8], 0x0d);
		t5 ^= InverseMc(cttmp[9], 0x09);
		t5 ^= InverseMc(cttmp[10], 0x0e);
		t5 ^= InverseMc(cttmp[11], 0x0b);

		t7 = InverseMc(cttmp[8], 0x0b);
		t7 ^= InverseMc(cttmp[9], 0x0d);
		t7 ^= InverseMc(cttmp[10], 0x09);
		t7 ^= InverseMc(cttmp[11], 0x0e);

		cttmp[8] = t0;
		cttmp[9] = t3;
		cttmp[10] = t5;
		cttmp[11] = t7;

		t0 = InverseMc(cttmp[12], 0x0e);
		t0 ^= InverseMc(cttmp[13], 0x0b);
		t0 ^= InverseMc(cttmp[14], 0x0d);
		t0 ^= InverseMc(cttmp[15], 0x09);

		t3 = InverseMc(cttmp[12], 0x09);
		t3 ^= InverseMc(cttmp[13], 0x0e);
		t3 ^= InverseMc(cttmp[14], 0x0b);
		t3 ^= InverseMc(cttmp[15], 0x0d);

		t5 = InverseMc(cttmp[12], 0x0d);
		t5 ^= InverseMc(cttmp[13], 0x09);
		t5 ^= InverseMc(cttmp[14], 0x0e);
		t5 ^= InverseMc(cttmp[15], 0x0b);

		t7 = InverseMc(cttmp[12], 0x0b);
		t7 ^= InverseMc(cttmp[13], 0x0d);
		t7 ^= InverseMc(cttmp[14], 0x09);
		t7 ^= InverseMc(cttmp[15], 0x0e);

		cttmp[12] = t0;
		cttmp[13] = t3;
		cttmp[14] = t5;
		cttmp[15] = t7;


		PrintValue(cttmp);


	}
	// round 1

	// inverse shift row
	// ��ȭ x
	for (int j = 0; j < Nw; j++)
	{
		w[j] = (cttmp[j] << 24) ^ (cttmp[4 + j] << 16) ^ (cttmp[8 + j] << 8) ^ (cttmp[12 + j]);
	}
	for (int j = 0; j < Nw; j++)
	{
		printf("w[%d]:%x \n", j, w[j]);
	}

	//rotate (�̺κи� ��ȭ)
	w[1] = (w[1] >> 8) ^ ((w[1] & 0x000000ff) << 24);
	w[2] = (w[2] >> 16) ^ ((w[2] & 0x0000ffff) << 16);
	w[3] = (w[3] >> 24) ^ ((w[3] & 0x00ffffff) << 8);


	//32bit�� 8bit��(��ȭX)
	for (int j = 0; j < Nw; j++)
	{
		cttmp[j] = ((w[j] & 0xff000000) >> 24) & 0xff;
		cttmp[4 + j] = ((w[j] & 0x00ff0000) >> 16) & 0xff;
		cttmp[8 + j] = ((w[j] & 0x0000ff00) >> 8) & 0xff;
		cttmp[12 + j] = ((w[j] & 0x000000ff)) & 0xff;
	}
	printf("DES = Inverse sr:");
	PrintValue(cttmp);

	//subbyte
	for (int j = 0; j < Nb; j++)
	{
		cttmp[j] = rsbox[cttmp[j]];
	}

	//addroundkey
	for (int i = 0; i < Nb; i++)
	{
		cttmp[i] = cttmp[i] ^ Rkey[0][i];  //������Ű
	}
	printf("DES = FiN:");
	PrintValue(cttmp);


}
