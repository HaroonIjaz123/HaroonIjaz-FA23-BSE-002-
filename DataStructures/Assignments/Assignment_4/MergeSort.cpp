#include<iostream>
using namespace std;
#define size 11
int arr[size];
void print_array(int arr[size]){
    for(int i = 0; i < size; i++){
        cout << arr[i] << " ";
    }
    cout << endl;
}
void merge(int arr[], int left, int mid, int right){
    int n1 = mid - left + 1;
    int n2 = right - mid;

    int L[n1], R[n2];

    for(int i = 0; i < n1; i++)
        L[i] = arr[left + i];
    for(int j = 0; j < n2; j++)
        R[j] = arr[mid + 1 + j];

    int i = 0, j = 0, k = left;
    while(i < n1 && j < n2){
        if(L[i] <= R[j]){
            arr[k] = L[i];
            i++;
        } else {
            arr[k] = R[j];
            j++;
        }
        k++;
    }
    while(i < n1){
        arr[k] = L[i];
        i++; k++;
    }

    while(j < n2){
        arr[k] = R[j];
        j++; k++;
    }
    print_array(arr);
}
void mergeSort(int arr[], int left, int right){
    if(left < right){
        int mid = (left + right) / 2;
        mergeSort(arr, left, mid);
        mergeSort(arr, mid + 1, right);
        merge(arr, left, mid, right);
    }
}
int main(){ 
    arr[0]=38;
    arr[1]=27;
    arr[2]=43;
    arr[3]=3;
    arr[4]=9;
    arr[5]=82;  
    arr[6]=10;
    arr[7]=12;
    arr[8]=5;
    arr[9]=7;
    arr[10]=1;
    print_array(arr);
    mergeSort(arr, 0, size - 1);
//    print_array(arr);
    return 0;
}
