#include <iostream>
using namespace std;

void foo(int &a){
    cout << "a in foo = " << a << endl;
    a++;
}

void foo2(int *b){
    cout << "b in foo = " << b << endl;
    (*b)++;
}

int main(int argc, char const *argv[])
{
    int a = 5;
    int b = 5;

    foo(a);
    
    int *tempB = &b;
    cout << "tempB = " << tempB << endl;
    foo2(tempB);
    
    cout << "a = " << a;
    cout << endl;
    cout << "*tempB = " << *tempB << endl;
    cout << "b = " << b << endl;


    int x = 6;
    int &y = x;
    int z = y;
    
    cout << "y = " << y << endl;

    return 0;
}
