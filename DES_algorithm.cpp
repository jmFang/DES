#include<iostream>
#include<vector>
#include<algorithm>
#include"desHeader.h"
using namespace std;


void initialPermutation(string& plainText);
vector<string> input();
string hexToBinary(char c);
string preHandle(string data);
vector<string> createSubKeys(string key);
void leftShit(string& LorR,  int n);
void reverse(string& str, int begin, int end);
void initialPermutation(string& plainText);
string DES(string& plainText, string& binaryKey);
string ExtendPermutation(string R);
string R_XOR_subKey(string Ex_R, string subKey, int mode);
string SBoxTransfer(string str);
int biToOct(string str);
string pPermutation(string str);
string ReverseIP(string str);




/*
* ��ʼ������ 
*/
 
/*
* ����ģ�� 
*/
vector<string> input() {
	string plainText, key;
	vector<string> out;
	cout << "���������ĺ���Կ���Կո����"<< endl;
	cout << "���ģ�";
	cin >> plainText;
	cout << "��Կ��";
	cin >> key;
	if(plainText.length() != 16 || key.length() != 16) {
		cout << "���Ļ���Կ�ĳ��Ȳ��ԣ�����������" << endl;
		do {
			cout << "���ģ�";
			cin >> plainText;
			cout << "��Կ��";
			cin >> key;
		} while(plainText.length() == 16 && key.length() && 16);
	}
	out.push_back(plainText);
	out.push_back(key);
	return out;
}
/*
* ʮ������ת������ 
*/
string hexToBinary(char c) {
	if(c == '0') {
		return "0000";
	} else if( c == '1') {
		return "0001";
	} else if( c == '2') {
		return "0010";
	} else if( c == '3') {
		return "0011";
	} else if( c == '4') {
		return "0100";
	} else if( c == '5') {
		return "0101";
	} else if( c == '6') {
		return "0110";
	} else if( c == '7') {
		return "0111";
	} else if( c == '8') {
		return "1000";
	} else if( c == '9') {
		return "1001";
	} else if( c == 'A') {
		return "1010";
	} else if( c == 'B') {
		return "1011";
	} else if( c == 'C') {
		return "1100";
	} else if( c == 'D') {
		return "1101";
	} else if( c == 'E') {
		return "1110";
	} else if( c == 'F') {
		return "1111";
	}
} 
/*
* Ԥ����ģ�� 
*/ 
string preHandle(string data) {
	string out = "";
	
	transform(data.begin(), data.end(), data.begin(), ::toupper);
	
	for(int i = 0; i < data.size(); i++) {
		out += hexToBinary(data[i]);
	}
	
	return out;
} 

/*
* ��������Կģ�� 
*/

vector<string> createSubKeys(string key) {
	
	string out = "", tmp = "";
	vector<string> res;
	string left_28 = "", right_28 = "";
	//����56λ��Կ 
	for(int i = 0; i < key.size(); i++) {
		if( (i+1) % 8 != 0) {
			out += key[i];
		}
	}
	//��Ϊ���������� 
	for(int i = 0; i < out.length(); i++) {
		if(i <= 27) {
			left_28 += out[i];
		} else {
			right_28 += out[i];
		}
	}
	//����16������Կ
	for(int k = 0; k < 16; k++) {
		leftShit(left_28, LeftShiftTable[k]);
		leftShit(right_28, LeftShiftTable[k]);
		
		string combineKey = left_28 + right_28;
		
		//�û�ѡ�񣬴�56λ��combineKey ��ѡ��48λ
		for(int i = 0; i < 48; i++) {
			int index = PC2Table[i] - 1;
			tmp += combineKey[index];
		}
		
		//����������Կ���뷵�ؽ�����м������� 
		res.push_back(tmp);
		tmp = "";	
	} 
	return res;
	
} 

/*
* ѭ������nλ 
*/ 

void leftShit(string& LorR,  int n) {
	reverse(LorR, 0, n-1);
	reverse(LorR, n, 27);
	reverse(LorR, 0, 27);
} 

/*
* �������� 
*/

void reverse(string& str, int begin, int end) {
	char tmp;
	for( ; begin < end; begin++, end--) {
		tmp = str[end];
		str[end] = str[begin];
		str[begin] = tmp;
	}
}

/*
* ��ʼ�û� 
*/

void initialPermutation(string& plainText) {
	//�ȿ���һ��	
	string res = plainText.c_str();
	
	for(int i = 0; i < 64; i++) {
		int index = IPTable[i] - 1;
		plainText[i] = res[index]; 
	}
	
}

/*
* ���ܵ���Ҫ���� (����16�ֵ��� �������ϲ��� 
*/

string DES(string& plainText, string& binaryKey) {
	
	//��ʼ�û� 
	initialPermutation(plainText);
	
	// ��������Կ
	vector<string> subKeys;
	subKeys =  createSubKeys(binaryKey);
	
	//�����ķ�Ϊ����
	string L(plainText.begin(), plainText.begin()+32);  
	string R(plainText.begin()+32, plainText.end());
	//cout << "L: " << L << "size: " << L.size() << endl;
	//cout << "r��" << R << "size: " << R.size() << endl;
	//16�ֵ��� 
	for(int k = 0; k < 16; k++) {
		
		string Rcopy = R;
		//E-��չ�û����õ�48λ��extend_R 
		string extend_R = ExtendPermutation(R);
		//cout << "extend_R's size: " <<  extend_R.size() << endl;
		
		//����չ���R������ԿK�������, ģʽ0��ʾ48λ֮������ 
		string XOR_result = R_XOR_subKey(extend_R, subKeys[k], 0);	
		//cout << "XOR_result size: " << XOR_result.size() << endl;
		
		//S�б任���õ�32λ���ɼ��ܺ���F�Ľ��
		string SBoxResult = SBoxTransfer(XOR_result);
		//cout << "SBoxResult size : " << SBoxResult.size() << endl;
		
		//�ڶ� SBoxResult ����һ��P�û�
		string afterP_permu = pPermutation(SBoxResult);
		//cout << "afterP_permu size : " << afterP_permu.size() << endl;
		
		//L��R��򣬵õ��������յ�R
		R = R_XOR_subKey(afterP_permu, L, 1);
		L = Rcopy;
	}
	
	string tmpResult = R + L;
	//cout << "tmpResult size: " << tmpResult.size() << endl;
	// �ٽ���һ�����ʼ�û�
	
	string finalResult = ReverseIP(tmpResult);
	
	//��ɼ��� 
	return  finalResult;

}

/*
* E-��չ�û� 
*/
string ExtendPermutation(string R) {
	string extendedR(48, 'a');
	for(int i = 0; i < 48; i++) {
		int index = ExtendedTable[i] - 1;
		extendedR[i] = R[index];
	} 
	return extendedR;
}
/*
* R������Կ��� 
*/ 
string R_XOR_subKey(string R, string subKey, int mode) {
	
	string res = "";
	if(mode == 0) {
		for(int i = 0; i < 48; i++) {
			if(R[i] == subKey[i]) {
				res += "0";
			} else {
				res += "1";
			}
		}		
	} else if( mode == 1) {	
		for(int i = 0; i < 32; i++) {
			if(R[i] == subKey[i]) {
				res += "0";
			} else {
				res += "1";
			}
		}	
	}
	return res;
} 

/*
* S �б任 
*/
string SBoxTransfer(string str) {
	
	string res = "";
	
	for(int s = 0; s < 8; s++) {
		
		// ÿ6λһ�飬�õ�8���Ӧ8��S�� 
		string group = "";
		for(int i = 0; i < 6; i++) {
			group += str[s * 6 + i];
		}
		
		//��group�����S�е��к��еĶ����Ʊ�ʾ
		string row = "";
		row += group[0];
		row += group[5];
		
		string col(group.begin()+1, group.end()-1); 
		col = "00" + col;

		//�����ƴ�תʮ���ƣ��õ�ÿһ�����S�е��к��в���
		int x = biToOct(row);
		int y = biToOct(col); 	
		
		//���н���õ�S�е�Ԫ��
		int target = SBox[s][x][y];
		 
		//��target���ɶ����ƴ�
		string binarySubstr = HexBiTable[target];
		
		 //������res��
		 res +=  binarySubstr;	
	}
	return res;
} 

/*
* �������ַ���תʮ���� 
*/
int biToOct(string str) {
	
	for(int i = 0; i < 16; i++) {
		if(HexBiTable[i] == str)
			return i;
	}
}

/*
* P�û� 
*/

string pPermutation(string str) {
	string res = str;
	
	for(int i = 0; i < 32; i++) {
		int index = PTable[i] - 1;
		res[i] = str[index];
	}
	return res;
}

/*
* ���ʼ�û� 
*/

string ReverseIP(string str)  {
	string res = str;
	
	for(int i = 0; i < 64; i++ ) {
		int index = RIPTable[i] - 1;
		res[i] = str[index];
	}
	return res;
}
/*
* ���� 
*/
int main() {
	vector<string> inputStr = input();
	//���ĳ�ʼ�û� 
	string text = preHandle(inputStr[0]);
	string key = preHandle(inputStr[1]);
	cout << "����ǰ���ģ�" << text << endl << "size: " << text.size() << endl;
	
	// ������Ҫ����,�õ��������� 
	string Ciphertext = DES(text, key);
	cout << "���ģ�"  << Ciphertext << endl << "size: " << Ciphertext.size() << endl;
	
	 
}
