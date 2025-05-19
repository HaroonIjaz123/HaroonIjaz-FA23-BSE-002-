
#include <iostream>
#include <algorithm>
using namespace std;
const int MAX_SIZE = 50;
int H[MAX_SIZE];
int heapSize = -1;
int parent(int i) { 
    return (i - 1) / 2;
 }
int leftChild(int i) { return (2 * i) + 1; 
}
int rightChild(int i) { 
    return (2 * i) + 2; 
}
void shiftUp(int i) {
    while (i > 0 && H[parent(i)] > H[i]) {
        swap(H[parent(i)], H[i]);
        i = parent(i);
    }
}
void insert(int p) {
    if (heapSize + 1 == MAX_SIZE) {
        cout << "Heap is full!" << endl;
        return;
    }
    heapSize++;
    H[heapSize] = p;
    shiftUp(heapSize);
}

void shiftDown(int i) {
    int minIndex = i;
    int l = leftChild(i);
    if (l <= heapSize && H[l] < H[minIndex]) {
        minIndex = l;
    }
    int r = rightChild(i);
    if (r <= heapSize && H[r] < H[minIndex]) {
        minIndex = r;
    }
    if (i != minIndex) {
        swap(H[i], H[minIndex]);
        shiftDown(minIndex);
    }
}

int deleteRoot() {
    if (heapSize == -1) {
        cout << "Heap is empty!" << endl;
        return -1;
    }
    int result = H[0];
    H[0] = H[heapSize];
    heapSize--;
    shiftDown(0);
    return result;
}

void display() {
    for (int i = 0; i <= heapSize; i++) {
        cout << H[i] << " ";
    }
    cout << endl;
}

int main() {
    insert(5);
    insert(3);
    insert(10);
    insert(1);
    insert(4);
    insert(2);
    cout << "Min Heap after insertion: ";
    display();
    cout << "Deleted Min Element is " << deleteRoot() << endl;
    cout << "Min Heap after Deletion: ";
    display();
    cout << "Deleted Min Element is " << deleteRoot() << endl;
    cout << "Min Heap after Deletion: ";
    display();
    return 0;
}
