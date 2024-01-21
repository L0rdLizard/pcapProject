#include <iostream>
using namespace std;

void foo(int &a){
    a++;
}

void foo2(int *b){
    b++;
}

int main(int argc, char const *argv[])
{
    int a = 5;
    int b = 5;

    foo(a);
    int *tempB = &b;
    foo2(tempB);
    
    cout << a;
    cout << endl;
    cout << *tempB << endl;

    return 0;
}
