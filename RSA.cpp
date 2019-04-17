#include<cstdio>
#include<algorithm>
#include<iostream>
#include<time.h>
#include "xxhash.c"
#include "xxhash.h"

using namespace std;


unsigned __int64 SMA(unsigned __int64 num, unsigned __int64 exponent, unsigned __int64 m) {
	if (exponent == 0) return 1;
	if (exponent == 1) return num;

	if (exponent % 2 == 0)
		return SMA((num*num) % m, exponent / 2, m);
	else
		return (num * SMA((num*num) % m, exponent / 2, m)) % m;



}//A.	Square and multiply algorithm for modular exponentiation
 //num은 밑, exponent는 승수, m은 모듈 연산...

bool MRPA(unsigned __int64 num) {
	srand((unsigned)time(NULL));
	unsigned __int64 s = 0;
	unsigned __int64 d;

	//밀러라빈 테스트를 위하여 n-1을 (2^s)*d의 꼴로 만들자
	unsigned __int64 temp = num - 1;
	while (true) {
		if (temp % 2 == 1)
			break;
		s++;
		temp = temp / 2;
	}
	d = temp;
	if (s == 0)
		return false;
	for (int i = 0; i < 20; i++) {//20번 검사 시도...

		unsigned __int64 a = rand() % (num - 3);
		a = a + 2;//pick a random integer a in the range [2, n − 2]
		unsigned __int64 x = SMA(a, d, num);
		if (x == 1 || x == num - 1)
			continue;
		bool continueCheck = false;
		for (int r = 0; r < s - 1; r++) {
			x = (x * x) % num;
			if (x == 1)
				return false;
			if (x == num - 1) {
				continueCheck = true;
				break;
			}

		}//r-1번 반복
		if (continueCheck == true)
			continue;
		return false;
	}
	return true;
}//B.	Miller-Rabin Primality test (테스트는 20회로 설정)
 //num은 소수인지 판정될 숫자...
 //true리턴시 소수, false는 합성수
 //테스트를 위한 숫자는 3 초과여야한다. 5부터 검사가능...
 //https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test
 //참고링크


long long EEA(unsigned __int64 m, unsigned __int64 b) {
	long long a1, a2, a3, b1, b2, b3;
	a1 = 1;
	a2 = 0;
	a3 = m;

	b1 = 0;
	b2 = 1;
	b3 = b;
	while (true) {
		if (b3 == 0)
			return -1;//m에대한 b의 역원이 존재하지 않는다.
		if (b3 == 1) {
			while (true) {
				if (b2 >= 0)
					break;
				b2 = b2 + m;
			}
			return b2 % m;//m에 대한 b의 역원을 0<=b2<m에 존재할수있게 작업
		}
		long long q = a3 / b3;
		long long t1, t2, t3;

		t1 = a1 - q * b1;
		t2 = a2 - q * b2;
		t3 = a3 - q * b3;

		a1 = b1;
		a2 = b2;
		a3 = b3;

		b1 = t1;
		b2 = t2;
		b3 = t3;
	}

}//Extended Euclidean Algorithm
 //처리과정 중에 음수 발생을 고려하여 long long으로 선언

unsigned __int64 CRTA(unsigned __int64 c, unsigned __int64 d, unsigned __int64 m1, unsigned __int64 m2, unsigned __int64 m3, unsigned __int64 M, unsigned __int64 e) {
	unsigned __int64 dp = EEA(m1 - 1, e);//d의 의미가 토션트n에대한 e의 역원이다 그러므로 p,q,r로 나누어서 계산을 진행할때
										 //토션트n이 아닌 토션트p, q, r에 대한 각각의 e의 역원을 구해주자... d를 그냥 쓰는 것 보다 크기가 많이 줄어든다.
	unsigned __int64 dq = EEA(m2 - 1, e);
	unsigned __int64 dr = EEA(m3 - 1, e);

	unsigned __int64 a1 = SMA(c%m1, dp, m1);//c^d mod m1 .... 결국 c...d개,,,c 가 존재하고 모든 c를 곱하는 과정에서 c mod m1를 통하여 c의 크기를 낮출 수 있다.
											//(c mod m1)(c mod m1)... d개...(c mod m1) == {c...d개...c}mod m1
	unsigned __int64 a2 = SMA(c%m2, dq, m2);
	unsigned __int64 a3 = SMA(c%m3, dr, m3);

	unsigned __int64 M1 = M / m1;
	unsigned __int64 M2 = M / m2;
	unsigned __int64 M3 = M / m3;

	unsigned __int64 c1 = EEA(m1, M1)*M1;
	unsigned __int64 c2 = EEA(m2, M2)*M2;
	unsigned __int64 c3 = EEA(m3, M3)*M3;

	return (a1*c1 + a2 * c2 + a3 * c3) % M;
}//중국인 나머지 정리 알고리즘... 
 //c1, c2, c3를 미리 계산하여 처리할 수 있다.
unsigned __int64 gcd(int a, int b) {
	return b ? gcd(b, a%b) : a;
}//유클리드 호제법

unsigned __int64 p, q, r, e, n;
unsigned __int64 Tn;//토션트n
					//p,q,r은 1023크기까지...
unsigned __int64 d;
unsigned __int64 msg;

unsigned __int64 cipher;
unsigned __int64 decryptionCipher;

unsigned __int64 hashMsg;
unsigned __int64 signature;
unsigned __int64 verifyVal;


void initVal() {
	srand((unsigned)time(NULL));
	while (true) {
		p = rand() % 1024;//0~1023 10bit...
		if (MRPA(p) == true || p == 2 || p == 3)
			break;
	}//밀러로빈 알고리즘에서 3,2는 소수판별 불가...

	while (true) {
		q = rand() % 1024;
		if (MRPA(q) == true || q == 2 || q == 3) {
			if (p != q)
				break;
		}

	}//밀러로빈 알고리즘에서 3,2는 소수판별 불가...

	while (true) {
		r = rand() % 1024;
		if (MRPA(r) == true || r == 2 || r == 3) {
			if (p != r && q != r)
				break;
		}

	}//밀러로빈 알고리즘에서 3,2는 소수판별 불가...
	 //서로 다른 소수를 만들기 위하여

	n = p * q * r;
	Tn = (p - 1)*(q - 1)*(r - 1);
	while (true) {
		e = rand() % (Tn - 2);//0<=e<=Tn-3
		e = e + 2;//2<=e<=Tn-1
		if (gcd(e, Tn) == 1)
			break;
	}//인크립션 키
	d = EEA(Tn, e);//Tn에대한 e의 역원... 디크립션 키 만들기...


}//변수 초기화

unsigned __int64 encryption(unsigned __int64 key, unsigned __int64 m, unsigned __int64 M) {
	return SMA(m, key, M);
}//public키로 암호화 ...  메세지를 
unsigned __int64 decryption(unsigned __int64 key, unsigned __int64 c, unsigned __int64 M, unsigned __int64 m1, unsigned __int64 m2, unsigned __int64 m3, unsigned __int64 e) {
	return CRTA(c, key, m1, m2, m3, M, e);
}//private키로 해독

unsigned __int64 makeHashMsg(unsigned __int64 msg, unsigned __int64 M) {
	char buf[64];
	sprintf(buf, "%I64u", msg);
	return XXH64(buf, sizeof(buf), 0) % M;

}
unsigned __int64 makeSig(unsigned __int64 hashMsg, unsigned __int64 privateKey, unsigned __int64 m1, unsigned __int64 m2, unsigned __int64 m3, unsigned __int64 M, unsigned __int64 publicKey) {
	return CRTA(hashMsg, privateKey, m1, m2, m3, M, publicKey);
}
unsigned __int64 verifySig(unsigned __int64 sig, unsigned __int64 key, unsigned __int64 n) {
	return SMA(sig, key, n);
}


int main() {
	initVal();
	cout << "p = " << p << "\n";
	cout << "q = " << q << "\n";
	cout << "r = " << r << "\n";
	cout << "N = " << n << "\n";
	cout << "Phi = " << Tn << "\n";
	cout << "e = " << e << "\n";
	cout << "d = " << d << "\n";
	cout << "\n";


	cout << "Message Input : ";
	cin >> msg;
	cout << "Message : " << msg << "\n";
	cout << "\n";

	cipher = encryption(e, msg, n);
	cout << "**Encryption\n";
	cout << "cipher : " << cipher << "\n";
	cout << "\n";
	hashMsg = makeHashMsg(msg, n);
	signature = makeSig(hashMsg, d, p, q, r, n, e);
	cout << "**Generate signature\n";
	cout << "message's hash value : " << hashMsg << "\n";
	cout << "generated signature : " << signature << "\n";
	cout << "\n";
	decryptionCipher = decryption(d, cipher, n, p, q, r, e);
	cout << "**Decryption\n";
	cout << "decrypted cipher : " << decryptionCipher << "\n";
	cout << "\n";
	cout << "**Verify signature\n";
	cout << "received signature value : " << signature << "\n";
	cout << "decrpted message's hash value : " << hashMsg << "\n";
	verifyVal = verifySig(signature, e, n);
	cout << "verify value from signature : " << verifyVal << "\n";
	if (verifyVal == hashMsg) {
		cout << "Signature valid!\n";
	}
	else {
		cout << "Signature not valid!\n";
	}
	return 0;

}