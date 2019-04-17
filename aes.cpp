#include<iostream>
#include<cstring>
#include<string>
#include<stdio.h>
#include <stdlib.h>

using namespace std;
unsigned char cipherResult[16];
unsigned char decrpytResult[16];
//아핀 매트릭스는 주어진 다항식으로 만들 수 있다.
unsigned char plainText[17];
unsigned char key[17];
unsigned char roundKey[11][4][4];//라운드 별 키 테이블
unsigned char tempText[4][4];//인크립션의 과정 도중의 텍스트 저장. 
unsigned int rc[11];
unsigned char tempKey[4][4];//키 계산을 위한 임시공간

unsigned int IP = 0b101101001;//Irreducible Polynomials
unsigned int IT[17][17];//inverse table;
unsigned char sBox[17][17];//에스박스
unsigned char inverseSBox[17][17];//역에스박스
unsigned char tempResultR[4];//r을 돌릴때 결과 저장...

unsigned char mixColumTable[4][4] = {
	{ 0x2, 0x3, 0x1, 0x1 },
{ 0x1, 0x2, 0x3, 0x1 },
{ 0x1, 0x1, 0x2, 0x3 },
{ 0x3, 0x1, 0x1, 0x2 } };//믹스컬럼테이블
unsigned char inverseMixColumTable[4][4] = {
	{ 0xe, 0xb, 0xd, 0x9 },
{ 0x9, 0xe, 0xb, 0xd },
{ 0xd, 0x9, 0xe, 0xb },
{ 0xb, 0xd, 0x9, 0xe } };//역믹스컬럼테이블


bool affineTable[8][8] = { { 1,0,0,0,1,1,1,1 } };//아핀테이블
bool tempInverseBit[8];//역원을 행렬화 시킨 것을 잠시 저장할 공간...
bool tempMulMatResult[8];//sbox를 만들기 위하여 아핀테이블과 역원의 곱을 저장...
bool sboxConstBit[8] = { 1,0,1,0,1,0,0,0 };//0x15를 이진수로 행렬화 시킴..
bool tempSboxBit[8];//sbox의 결과를 비트로 저장.

unsigned char substituteFunction(unsigned char input) {
	unsigned char output = sBox[input >> 4][input&(0b00001111)];
	return output;
}//substitute함수
unsigned char inverseSubstituteFunction(unsigned char input) {
	unsigned char output = inverseSBox[input >> 4][input&(0b00001111)];
	return output;
}//역substitute함수

unsigned int gadd(unsigned int a, unsigned int b) {
	return a ^ b;
}//갈로이스필드에서 더하기
unsigned char gmul(unsigned char a, unsigned char b) {
	unsigned char p = 0;
	unsigned char counter;
	unsigned char hi_bit_set;
	for (counter = 0; counter < 8; counter++) {
		if ((b & 1) == 1)
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if (hi_bit_set == 0x80)//최상위비트가 켜졌을때 그에 맞게 치환...(x^6+x^5+x^3+1)
			a ^= 0b1101001;
		b >>= 1;
	}
	return p;
}//gf 곱하기

unsigned int bitMul(unsigned int a, unsigned int b) {
	unsigned int p = 0;
	for (int i = 0; i < 8; i++) {
		if ((b & 1) == 1)
			p ^= a;
		a = a << 1;
		b = b >> 1;//한칸 줄이기
	}//캐리고려 없이 2진수 곱 연산

	return p;
}//2진수 곱하기
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
	}//임시공간에 매트릭스 곱을 저장하고
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] = tempMixResultTable[i][j];
		}
	}//다시 원래 임시 텍스트에 넣어주자
}//믹스컬럼 함수
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
}//믹스컬럼 역 함수
void makeKeyTable() {
	int presentKeyIdx = 0;//현제 키의 위치
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempKey[j][i] = key[presentKeyIdx];
			roundKey[0][j][i] = key[presentKeyIdx];//0(시작)라운드 키 저장 
			presentKeyIdx++;
		}
	}
}//받은 키를 4*4행렬로 저장

void addRoundKey(int presentRound) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[i][j] ^= roundKey[presentRound][i][j];
		}
	}
}//라운드별 키를 더해주는 함수
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
	}//오른쪽으로 i만큼 순환 시프트
}//시프트로우 함수
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
	}//시프트로우 함수가 수행한 과정을 반대로 수행하자.
}//시프트로우 역함수
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

	//필요에 맞는 함수를 호출하여 각 라인별로 수행결과 출력
}//인크립션 마지막라운드 수행
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

	//필요에 맞는 함수를 호출하여 각 라인별로 수행결과 출력

}//디크립션 마지막라운드 수행

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
	//필요에 맞는 함수를 호출하여 각 라인별로 수행결과 출력

}//인크립션 n 라운드 처리
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


	//필요에 맞는 함수를 호출하여 각 라인별로 수행결과 출력
}//n 라운드 디크립션 처리

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

	//필요에 맞는 함수를 호출하여 각 라인별로 수행결과 출력
}//인크립션 0라운드는 따로 처리

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

	//필요에 맞는 함수를 호출하여 각 라인별로 수행결과 출력
}//0라운드 드크립션 따로 처리
void makeTextTable() {
	int presentTextIdx = 0;//현제 텍스트의 위치
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempText[j][i] = plainText[presentTextIdx];
			presentTextIdx++;
		}
	}
}//받은 텍스트를 4*4행렬로 저장

unsigned char tempRinput[4];
void Rfunction(int roundNum) {//R을 돌리는 순간의 라운드와 키의 인풋 라인의 넘버를 입력 받는다.

	for (int i = 3; i >= 0; i--) {
		tempRinput[i] = tempKey[(i + 1) % 4][3];
	}//오른쪽으로 순환 시프트
	tempResultR[0] = substituteFunction(tempRinput[0]) ^ rc[roundNum];//처음 0에서 rc xor 해주자...
	for (int i = 1; i < 4; i++) {
		tempResultR[i] = substituteFunction(tempRinput[i]);//나머지는 서브티튜함수만 수행
	}
}//r함수

void keyExpansion() {
	makeKeyTable();
	for (int i = 1; i <= 10; i++) {
		Rfunction(i);//각 라운드 별 r을 만들어주자...
					 //처음은 r과 따로
		for (int k = 0; k < 4; k++) {
			tempKey[k][0] = tempKey[k][0] ^ tempResultR[k];
		}//처음 세로 계산 수행...
		for (int j = 1; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				tempKey[k][j] ^= tempKey[k][j - 1];
			}
		}//나머지 세로 계산 수행...
		 //i라운드 키를 완성
		for (int j = 0; j < 4; j++) {
			for (int k = 0; k < 4; k++) {
				roundKey[i][j][k] = tempKey[j][k];
			}
		}

	}//10라운드 진행...

}




void makeMulMatrix() {
	memset(tempMulMatResult, 0, sizeof(tempMulMatResult));
	for (int i = 0; i < 8; i++) {
		unsigned int temp = 0;//임시로 행렬 곱 처리시 결과 값 저장
		for (int j = 0; j < 8; j++) {
			temp ^= affineTable[i][j] * tempInverseBit[j];
		}
		tempMulMatResult[i] = temp;
	}
}//아핀테이블과 역원의 행렬을 곱하는 함수...

void addConstSbox() {
	memset(tempSboxBit, 0, sizeof(tempInverseBit));
	for (int i = 0; i < 8; i++) {
		tempSboxBit[i] = tempMulMatResult[i] ^ sboxConstBit[i];
	}
}//affine테이블과 행렬 곱을 하고 주어진 0x15상수와 더해주자.

unsigned char convertSboxValH() {
	unsigned char sboxResult = 0;
	for (int i = 0; i < 8; i++) {
		if (tempSboxBit[i] == 1)
			sboxResult |= (1 << i);
	}
	return sboxResult;
}//bit(2진수)행렬로 저장되어있는 sbox값을 16진수로 변환하여 리턴

void makeTempInverseBit(unsigned char a) {
	memset(tempInverseBit, 0, sizeof(tempInverseBit));
	for (int i = 0; i < 8; i++) {
		tempInverseBit[i] = (a & 1);
		a = a >> 1;
	}
}//16진수로 받은 역원을 2진수로 행렬화
void makeAffineTable() {
	for (int i = 1; i < 8; i++) {
		affineTable[i][0] = affineTable[i - 1][7];
		for (int j = 1; j < 8; j++) {
			affineTable[i][j] = affineTable[i - 1][j - 1];
		}
	}
}//아핀테이블 만들어주자



unsigned int bitdiv(unsigned int a, unsigned int b) {
	unsigned int result = 0;
	while (true) {
		unsigned int aChek = 0b100000000;
		unsigned int bChek = 0b100000000;
		int alen = 9;
		int blen = 9;//높은자리의 위치를 각각 찾아 주자...
		while (true) {
			if ((a&aChek) != 0)//가장 높은자리 찾음
				break;
			alen--;
			aChek = aChek >> 1;
			if (alen == 0)
				break;
		}
		while (true) {

			if ((b&bChek) != 0)//가장 높은자리 찾음
				break;
			blen--;
			bChek = bChek >> 1;
			if (blen == 0)
				break;
		}
		if (alen < blen)//길이비교
			break;//더이상 못나누는 경우 탈출
		a = a >> (alen - blen);
		result += 1 << (alen - blen);
		if (alen - blen == 0)
			break;//더이상 못나누는 경우 탈출
	}
	return result;
}//이진수 나누기...


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

//plain, key를 bin에서 뽑고 파일을 닫아주자.

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
}//EXTENDED EUCLID 확장 유클리드 구현


void makeInverseSbox() {
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			unsigned char presentSboxVal = sBox[i][j];
			inverseSBox[presentSboxVal >> 4][presentSboxVal&(0b00001111)] = (i << 4) | (j);
		}
	}
}//역에스박스 구현


void makeITable() {
	unsigned int i = 0;
	while (true) {
		unsigned int tempMI = ExtendedEUCLID(IP, i);

		IT[i >> 4][i&(0b00001111)] = tempMI;
		if (i == 0xFF)
			break;
		i++;
	}
}//make inverse table ...역원 테이블 만들기
void makeSbox() {
	makeITable();//역원 테이블 구하기

	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			unsigned char presentI = IT[i][j];//현제 변환하고자 하는 역원의 값
			makeTempInverseBit(presentI);//역원을 행렬화
			makeMulMatrix();//아핀테이블과 곱하기
			addConstSbox();//상수값을 더하여 sbox 값 만들어주기
			sBox[i][j] = convertSboxValH();//행렬로 저장되어 있는 sbox를 16진수로 변환하여 저장
		}
	}//행렬의 연산을 통하여 sbox구현
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

	//main에서는 출력과 함수 호출만...
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