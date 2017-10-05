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
* 初始化数据 
*/
 
/*
* 输入模块 
*/
vector<string> input() {
	string plainText, key;
	vector<string> out;
	cout << "请输入明文和密钥，以空格隔开"<< endl;
	cout << "明文：";
	cin >> plainText;
	cout << "密钥：";
	cin >> key;
	if(plainText.length() != 16 || key.length() != 16) {
		cout << "明文或密钥的长度不对！请重新输入" << endl;
		do {
			cout << "明文：";
			cin >> plainText;
			cout << "密钥：";
			cin >> key;
		} while(plainText.length() == 16 && key.length() && 16);
	}
	out.push_back(plainText);
	out.push_back(key);
	return out;
}
/*
* 十六进制转二进制 
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
* 预处理模块 
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
* 产生子密钥模块 
*/

vector<string> createSubKeys(string key) {
	
	string out = "", tmp = "";
	vector<string> res;
	string left_28 = "", right_28 = "";
	//生成56位密钥 
	for(int i = 0; i < key.size(); i++) {
		if( (i+1) % 8 != 0) {
			out += key[i];
		}
	}
	//分为左右两部分 
	for(int i = 0; i < out.length(); i++) {
		if(i <= 27) {
			left_28 += out[i];
		} else {
			right_28 += out[i];
		}
	}
	//产生16个子密钥
	for(int k = 0; k < 16; k++) {
		leftShit(left_28, LeftShiftTable[k]);
		leftShit(right_28, LeftShiftTable[k]);
		
		string combineKey = left_28 + right_28;
		
		//置换选择，从56位的combineKey 中选出48位
		for(int i = 0; i < 48; i++) {
			int index = PC2Table[i] - 1;
			tmp += combineKey[index];
		}
		
		//产生的子密钥放入返回结果，中间变量清空 
		res.push_back(tmp);
		tmp = "";	
	} 
	return res;
	
} 

/*
* 循环左移n位 
*/ 

void leftShit(string& LorR,  int n) {
	reverse(LorR, 0, n-1);
	reverse(LorR, n, 27);
	reverse(LorR, 0, 27);
} 

/*
* 逆序排列 
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
* 初始置换 
*/

void initialPermutation(string& plainText) {
	//先拷贝一份	
	string res = plainText.c_str();
	
	for(int i = 0; i < 64; i++) {
		int index = IPTable[i] - 1;
		plainText[i] = res[index]; 
	}
	
}

/*
* 加密的主要部分 (包含16轮迭代 、互换合并） 
*/

string DES(string& plainText, string& binaryKey) {
	
	//初始置换 
	initialPermutation(plainText);
	
	// 产生子密钥
	vector<string> subKeys;
	subKeys =  createSubKeys(binaryKey);
	
	//将明文分为两半
	string L(plainText.begin(), plainText.begin()+32);  
	string R(plainText.begin()+32, plainText.end());
	//cout << "L: " << L << "size: " << L.size() << endl;
	//cout << "r：" << R << "size: " << R.size() << endl;
	//16轮迭代 
	for(int k = 0; k < 16; k++) {
		
		string Rcopy = R;
		//E-扩展置换，得到48位的extend_R 
		string extend_R = ExtendPermutation(R);
		//cout << "extend_R's size: " <<  extend_R.size() << endl;
		
		//将扩展后的R与子密钥K进行异或, 模式0表示48位之间的异或 
		string XOR_result = R_XOR_subKey(extend_R, subKeys[k], 0);	
		//cout << "XOR_result size: " << XOR_result.size() << endl;
		
		//S盒变换，得到32位的由加密函数F的结果
		string SBoxResult = SBoxTransfer(XOR_result);
		//cout << "SBoxResult size : " << SBoxResult.size() << endl;
		
		//在对 SBoxResult 进行一次P置换
		string afterP_permu = pPermutation(SBoxResult);
		//cout << "afterP_permu size : " << afterP_permu.size() << endl;
		
		//L与R异或，得到本轮最终的R
		R = R_XOR_subKey(afterP_permu, L, 1);
		L = Rcopy;
	}
	
	string tmpResult = R + L;
	//cout << "tmpResult size: " << tmpResult.size() << endl;
	// 再进行一次逆初始置换
	
	string finalResult = ReverseIP(tmpResult);
	
	//完成加密 
	return  finalResult;

}

/*
* E-扩展置换 
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
* R与子密钥异或 
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
* S 盒变换 
*/
string SBoxTransfer(string str) {
	
	string res = "";
	
	for(int s = 0; s < 8; s++) {
		
		// 每6位一组，得到8组对应8个S盒 
		string group = "";
		for(int i = 0; i < 6; i++) {
			group += str[s * 6 + i];
		}
		
		//由group构造出S盒的行和列的二进制表示
		string row = "";
		row += group[0];
		row += group[5];
		
		string col(group.begin()+1, group.end()-1); 
		col = "00" + col;

		//二进制串转十进制，得到每一组对用S盒的行和列参数
		int x = biToOct(row);
		int y = biToOct(col); 	
		
		//行列交叉得到S盒的元素
		int target = SBox[s][x][y];
		 
		//将target换成二进制串
		string binarySubstr = HexBiTable[target];
		
		 //加入结果res中
		 res +=  binarySubstr;	
	}
	return res;
} 

/*
* 二进制字符串转十进制 
*/
int biToOct(string str) {
	
	for(int i = 0; i < 16; i++) {
		if(HexBiTable[i] == str)
			return i;
	}
}

/*
* P置换 
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
* 逆初始置换 
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
* 测试 
*/
int main() {
	vector<string> inputStr = input();
	//明文初始置换 
	string text = preHandle(inputStr[0]);
	string key = preHandle(inputStr[1]);
	cout << "加密前明文：" << text << endl << "size: " << text.size() << endl;
	
	// 进入主要部分,得到加密密文 
	string Ciphertext = DES(text, key);
	cout << "密文："  << Ciphertext << endl << "size: " << Ciphertext.size() << endl;
	
	 
}
