#include<iostream>
#include<cstring>
#include<string>
#include<stdio.h>
#include <stdlib.h>

using namespace std;
unsigned char cipherResult[16];
unsigned char decrpytResult[16];
//���� ��Ʈ������ �־��� ���׽����� ���� �� �ִ�.
unsigned char plainText[17];
unsigned char key[17];
unsigned char roundKey[11][4][4];//���� �� Ű ���̺�
unsigned char tempText[4][4];//��ũ������ ���� ������ �ؽ�Ʈ ����. 
unsigned int rc[11];
unsigned char tempKey[4][4];//Ű ����� ���� �ӽð���

unsigned int IP = 0b101101001;//Irreducible Polynomials
unsigned int IT[17][17];//inverse table;
unsigned char sBox[17][17];//�����ڽ�
unsigned char inverseSBox[17][17];//�������ڽ�
unsigned char tempResultR[4];//r�� ������ ��� ����...

unsigned char mixColumTable[4][4] = {
	{ 0x2, 0x3, 0x1, 0x1 },
{ 0x1, 0x2, 0x3, 0x1 },
{ 0x1, 0x1, 0x2, 0x3 },
{ 0x3, 0x1, 0x1, 0x2 } };//�ͽ��÷����̺�
unsigned char inverseMixColumTable[4][4] = {
	{ 0xe, 0xb, 0xd, 0x9 },
{ 0x9, 0xe, 0xb, 0xd },
{ 0xd, 0x9, 0xe, 0xb },
{ 0xb, 0xd, 0x9, 0xe } };//���ͽ��÷����̺�


bool affineTable[8][8] = { { 1,0,0,0,1,1,1,1 } };//�������̺�
bool tempInverseBit[8];//������ ���ȭ ��Ų ���� ��� ������ ����...
bool tempMulMatResult[8];//sbox�� ����� ���Ͽ� �������̺�� ������ ���� ����...
bool sboxConstBit[8] = { 1,0,1,0,1,0,0,0 };//0x15�� �������� ���ȭ ��Ŵ..
bool tempSboxBit[8];//sbox�� ����� ��Ʈ�� ����.

unsigned char substituteFunction(unsigned char input) {
	unsigned char output = sBox[input >> 4][input&(0b00001111)];
	return output;
}//substitute�Լ�
unsigned char inverseSubstituteFunction(unsigned char input) {
	unsigned char output = inverseSBox[input >> 4][input&(0b00001111)];
	return output;
}//��substitute�Լ�

unsigned int gadd(unsigned int a, unsigned int b) {
	return a ^ b;
}//�����̽��ʵ忡�� ���ϱ�
unsigned char gmul(unsigned char a, unsigned char b) {
	unsigned char p = 0;
	unsigned char counter;
	unsigned char hi_bit_set;
	for (counter = 0; counter < 8; counter++) {
		if ((b & 1) == 1)
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if (hi_bit_set == 0x80)//�ֻ�����Ʈ�� �������� �׿� �°� ġȯ...(x^6+x^5+x^3+1)
			a ^= 0b1101001;
		b >>= 1;
	}
	return p;
}//gf ���ϱ�

unsigned int bitMul(unsigned int a, unsigned int b) {
	unsigned int p = 0;
	for (int i = 0; i < 8; i++) {
		if ((b & 1) == 1)
			p ^= a;
		a = a << 1;
		b = b >> 1;//��ĭ ���̱�
	}//ĳ����� ���� 2���� �� ����

	return p;
}//2���� ���ϱ�
unsigned char tempMixResultTable[4][4];
void mixColum() {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			unsigned char tempResultMix = 0;
			for (int k = 0; k < 4; k++) {
				tempResultMix = gadd(tempResultMix, gmul(mixColumTable[i][k], tempText[k][j]));
			}
			tempMixResultTable[i][j] = tempResultMix;
		}
	}//�ӽð����� ��Ʈ���� ���� �����ϰ�
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] = tempMixResultTable[i][j];
		}
	}//�ٽ� ���� �ӽ� �ؽ�Ʈ�� �־�����
}//�ͽ��÷� �Լ�
unsigned char inverseTempMixResultTable[4][4];
void inverseMixColum() {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			unsigned char tempResultMix = 0;
			for (int k = 0; k < 4; k++) {
				tempResultMix = gadd(tempResultMix, gmul(inverseMixColumTable[i][k], tempText[k][j]));
			}
			inverseTempMixResultTable[i][j] = tempResultMix;
		}
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] = inverseTempMixResultTable[i][j];
		}
	}
}//�ͽ��÷� �� �Լ�
void makeKeyTable() {
	int presentKeyIdx = 0;//���� Ű�� ��ġ
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempKey[j][i] = key[presentKeyIdx];
			roundKey[0][j][i] = key[presentKeyIdx];//0(����)���� Ű ���� 
			presentKeyIdx++;
		}
	}
}//���� Ű�� 4*4��ķ� ����

void addRoundKey(int presentRound) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] ^= roundKey[presentRound][i][j];
		}
	}
}//���庰 Ű�� �����ִ� �Լ�
void shiftRows() {
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < i; j++) {
			unsigned char savePast = tempText[i][0];
			unsigned char savePresent;
			for (int k = 3; k >= 0; k--) {
				savePresent = tempText[i][k];
				tempText[i][k] = savePast;
				savePast = savePresent;
			}
		}
	}//���������� i��ŭ ��ȯ ����Ʈ
}//����Ʈ�ο� �Լ�
void inverseShiftRows() {
	for (int i = 1; i < 4; i++) {
		for (int j = 0; j < i; j++) {
			unsigned char savePast = tempText[i][3];
			unsigned char savePresent;
			for (int k = 0; k <4; k++) {
				savePresent = tempText[i][k];
				tempText[i][k] = savePast;
				savePast = savePresent;
			}
		}
	}//����Ʈ�ο� �Լ��� ������ ������ �ݴ�� ��������.
}//����Ʈ�ο� ���Լ�
void roundF() {

	printf("Round %d\n", 10);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] = substituteFunction(tempText[i][j]);
		}
	}
	printf("SB: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");
	shiftRows();
	printf("SR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");
	addRoundKey(10);
	printf("AR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");

	//�ʿ信 �´� �Լ��� ȣ���Ͽ� �� ���κ��� ������ ���
}//��ũ���� ���������� ����
void roundFD() {

	printf("Round %d\n", 10);

	inverseShiftRows();
	printf("SR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] = inverseSubstituteFunction(tempText[i][j]);
		}
	}
	printf("SB: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");	addRoundKey(0);
	printf("AR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");

	//�ʿ信 �´� �Լ��� ȣ���Ͽ� �� ���κ��� ������ ���

}//��ũ���� ���������� ����

void roundN(int presentRound) {
	printf("Round %d\n", presentRound);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] = substituteFunction(tempText[i][j]);
		}
	}
	printf("SB: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");
	shiftRows();
	printf("SR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");
	mixColum();
	printf("MC: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");
	addRoundKey(presentRound);
	printf("AR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");
	//�ʿ信 �´� �Լ��� ȣ���Ͽ� �� ���κ��� ������ ���

}//��ũ���� n ���� ó��
void roundND(int presentRound) {
	printf("Round %d\n", presentRound);
	inverseShiftRows();
	printf("SR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] = inverseSubstituteFunction(tempText[i][j]);
		}
	}
	printf("SB: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");

	addRoundKey(10 - presentRound);
	printf("AR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");
	inverseMixColum();
	printf("MC: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");


	//�ʿ信 �´� �Լ��� ȣ���Ͽ� �� ���κ��� ������ ���
}//n ���� ��ũ���� ó��

void roundZero() {
	addRoundKey(0);
	printf("Round 0\n");
	printf("AR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");

	//�ʿ信 �´� �Լ��� ȣ���Ͽ� �� ���κ��� ������ ���
}//��ũ���� 0����� ���� ó��

void roundZeroD() {
	addRoundKey(10);
	printf("Round 0\n");
	printf("AR: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
		}
	}
	printf("\n");

	//�ʿ信 �´� �Լ��� ȣ���Ͽ� �� ���κ��� ������ ���
}//0���� ��ũ���� ���� ó��
void makeTextTable() {
	int presentTextIdx = 0;//���� �ؽ�Ʈ�� ��ġ
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[j][i] = plainText[presentTextIdx];
			presentTextIdx++;
		}
	}
}//���� �ؽ�Ʈ�� 4*4��ķ� ����

unsigned char tempRinput[4];
void Rfunction(int roundNum) {//R�� ������ ������ ����� Ű�� ��ǲ ������ �ѹ��� �Է� �޴´�.

	for (int i = 3; i >= 0; i--) {
		tempRinput[i] = tempKey[(i + 1) % 4][3];
	}//���������� ��ȯ ����Ʈ
	tempResultR[0] = substituteFunction(tempRinput[0]) ^ rc[roundNum];//ó�� 0���� rc xor ������...
	for (int i = 1; i < 4; i++) {
		tempResultR[i] = substituteFunction(tempRinput[i]);//�������� ����ƼƩ�Լ��� ����
	}
}//r�Լ�

void keyExpansion() {
	makeKeyTable();
	for (int i = 1; i <= 10; i++) {
		Rfunction(i);//�� ���� �� r�� ���������...
					 //ó���� r�� ����
		for (int k = 0; k < 4; k++) {
			tempKey[k][0] = tempKey[k][0] ^ tempResultR[k];
		}//ó�� ���� ��� ����...
		for (int j = 1; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				tempKey[k][j] ^= tempKey[k][j - 1];
			}
		}//������ ���� ��� ����...
		 //i���� Ű�� �ϼ�
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				roundKey[i][j][k] = tempKey[j][k];
			}
		}

	}//10���� ����...

}




void makeMulMatrix() {
	memset(tempMulMatResult, 0, sizeof(tempMulMatResult));
	for (int i = 0; i < 8; i++) {
		unsigned int temp = 0;//�ӽ÷� ��� �� ó���� ��� �� ����
		for (int j = 0; j < 8; j++) {
			temp ^= affineTable[i][j] * tempInverseBit[j];
		}
		tempMulMatResult[i] = temp;
	}
}//�������̺�� ������ ����� ���ϴ� �Լ�...

void addConstSbox() {
	memset(tempSboxBit, 0, sizeof(tempInverseBit));
	for (int i = 0; i < 8; i++) {
		tempSboxBit[i] = tempMulMatResult[i] ^ sboxConstBit[i];
	}
}//affine���̺�� ��� ���� �ϰ� �־��� 0x15����� ��������.

unsigned char convertSboxValH() {
	unsigned char sboxResult = 0;
	for (int i = 0; i < 8; i++) {
		if (tempSboxBit[i] == 1)
			sboxResult |= (1 << i);
	}
	return sboxResult;
}//bit(2����)��ķ� ����Ǿ��ִ� sbox���� 16������ ��ȯ�Ͽ� ����

void makeTempInverseBit(unsigned char a) {
	memset(tempInverseBit, 0, sizeof(tempInverseBit));
	for (int i = 0; i < 8; i++) {
		tempInverseBit[i] = (a & 1);
		a = a >> 1;
	}
}//16������ ���� ������ 2������ ���ȭ
void makeAffineTable() {
	for (int i = 1; i < 8; i++) {
		affineTable[i][0] = affineTable[i - 1][7];
		for (int j = 1; j < 8; j++) {
			affineTable[i][j] = affineTable[i - 1][j - 1];
		}
	}
}//�������̺� ���������



unsigned int bitdiv(unsigned int a, unsigned int b) {
	unsigned int result = 0;
	while (true) {
		unsigned int aChek = 0b100000000;
		unsigned int bChek = 0b100000000;
		int alen = 9;
		int blen = 9;//�����ڸ��� ��ġ�� ���� ã�� ����...
		while (true) {
			if ((a&aChek) != 0)//���� �����ڸ� ã��
				break;
			alen--;
			aChek = aChek >> 1;
			if (alen == 0)
				break;
		}
		while (true) {

			if ((b&bChek) != 0)//���� �����ڸ� ã��
				break;
			blen--;
			bChek = bChek >> 1;
			if (blen == 0)
				break;
		}
		if (alen < blen)//���̺�
			break;//���̻� �������� ��� Ż��
		a = a >> (alen - blen);
		result += 1 << (alen - blen);
		if (alen - blen == 0)
			break;//���̻� �������� ��� Ż��
	}
	return result;
}//������ ������...


void pullKeyAndPlain() {
	FILE *plainFile;
	FILE *keyFile;

	fopen_s(&plainFile, "plain.bin", "rb");
	fopen_s(&keyFile, "key.bin", "rb");


	fread(plainText, sizeof(unsigned char), 16, plainFile);
	fread(key, sizeof(unsigned char), 16, keyFile);
	fclose(plainFile);
	fclose(keyFile);

}

//plain, key�� bin���� �̰� ������ �ݾ�����.

unsigned int ExtendedEUCLID(unsigned int m, unsigned int b) {
	unsigned int a1, a2, a3;
	unsigned int b1, b2, b3;
	a1 = 1;
	a2 = 0;
	a3 = m;

	b1 = 0;
	b2 = 1;
	b3 = b;

	while (true) {
		if (b3 == 0) {
			return 0;
		}
		if (b3 == 1) {
			return b2;
		}
		unsigned int t1, t2, t3;
		unsigned int q = bitdiv(a3, b3);

		t1 = gadd(a1, bitMul(b1, q));
		t2 = gadd(a2, bitMul(b2, q));
		t3 = gadd(a3, bitMul(b3, q));

		a1 = b1;
		a2 = b2;
		a3 = b3;

		b1 = t1;
		b2 = t2;
		b3 = t3;
	}
}//EXTENDED EUCLID Ȯ�� ��Ŭ���� ����


void makeInverseSbox() {
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			unsigned char presentSboxVal = sBox[i][j];
			inverseSBox[presentSboxVal >> 4][presentSboxVal&(0b00001111)] = (i << 4) | (j);
		}
	}
}//�������ڽ� ����


void makeITable() {
	unsigned int i = 0;
	while (true) {
		unsigned int tempMI = ExtendedEUCLID(IP, i);

		IT[i >> 4][i&(0b00001111)] = tempMI;
		if (i == 0xFF)
			break;
		i++;
	}
}//make inverse table ...���� ���̺� �����
void makeSbox() {
	makeITable();//���� ���̺� ���ϱ�

	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			unsigned char presentI = IT[i][j];//���� ��ȯ�ϰ��� �ϴ� ������ ��
			makeTempInverseBit(presentI);//������ ���ȭ
			makeMulMatrix();//�������̺�� ���ϱ�
			addConstSbox();//������� ���Ͽ� sbox �� ������ֱ�
			sBox[i][j] = convertSboxValH();//��ķ� ����Ǿ� �ִ� sbox�� 16������ ��ȯ�Ͽ� ����
		}
	}//����� ������ ���Ͽ� sbox����
	 /*
	 for (int i = 0; i < 16; i++) {
	 for (int j = 0; j < 16; j++) {
	 int presentI = IT[i][j];
	 sBox[i][j] = presentI ^(((presentI<<1)&(0b11111111))|(presentI>>7)) ^ (((presentI << 2)&(0b11111111)) | (presentI >> 6)) ^ (((presentI << 3)&(0b11111111)) | (presentI >> 5)) ^ (((presentI << 4)&(0b11111111)) | (presentI >> 4)) ^ (0x15);
	 }//
	 }
	 */
}
void makeCipherFile() {
	FILE *cipherFile;
	

	fopen_s(&cipherFile, "cipher.bin", "wb");
	fwrite(cipherResult, sizeof(unsigned char),16 , cipherFile);
	fclose(cipherFile);
}

void makeDecryptFile() {
	FILE *decryptFile;
	

	fopen_s(&decryptFile, "decrypt.bin", "wb");
	fwrite(decrpytResult, sizeof(unsigned char), 16, decryptFile);
	fclose(decryptFile);
}
void makeRc() {
	rc[1] = 0x01;
	for (int i = 2; i <= 10; i++) {
		if (rc[i - 1] >= 0x80) {
			unsigned int temp = rc[i - 1];
			temp = temp * 2;
			temp ^= IP;
			rc[i] = temp;
		}
		else {
			rc[i] = rc[i - 1] * 2;
		}
	}
}

int main() {
	makeRc();

	//main������ ��°� �Լ� ȣ�⸸...
	pullKeyAndPlain();
	makeAffineTable();
	makeSbox();

	keyExpansion();
	makeTextTable();

	printf("RC: ");
	for (int i = 1; i <= 10; i++) {
		printf("%02X ", rc[i]);
	}
	printf("\n");

	printf("PLAIN: ");
	for (int i = 0; i < 16; i++) {
		printf("%02X ", plainText[i]);
	}
	printf("\n");

	printf("KEY: ");
	for (int i = 0; i < 16; i++) {
		printf("%02X ", key[i]);
	}
	printf("\n");

	printf("\n");
	printf("<------ ENCRYPTION ------>\n");
	printf("\n");

	printf("KEY EXPANSION\n");
	for (int i = 0; i < 11; i++) {
		printf("ROUND %d: ", i);
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				printf("%02X ", roundKey[i][k][j]);
			}
		}
		printf("\n");
	}
	printf("\n");
	roundZero();
	for (int i = 1; i < 10; i++) {
		roundN(i);
		printf("\n");
	}
	roundF();
	printf("\n");
	printf("CIPHER: ");
	int cnt = 0;
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
			cipherResult[cnt] = tempText[k][j];
			cnt++;
		}
	}
	cnt = 0;
	makeCipherFile();
	printf("\n");
	printf("\n");
	printf("\n");

	printf("<------ DECRYPTION ------>\n");
	printf("\n");
	makeInverseSbox();
	roundZeroD();
	printf("\n");
	for (int i = 1; i < 10; i++) {
		roundND(i);
		printf("\n");
	}
	roundFD();
	printf("\n");
	printf("DECRYPTED: ");
	for (int j = 0; j < 4; j++) {
		for (int k = 0; k < 4; k++) {
			printf("%02X ", tempText[k][j]);
			decrpytResult[cnt] = tempText[k][j];
			cnt++;
		}
	}
	printf("\n");
	makeDecryptFile();
	system("pause");
}