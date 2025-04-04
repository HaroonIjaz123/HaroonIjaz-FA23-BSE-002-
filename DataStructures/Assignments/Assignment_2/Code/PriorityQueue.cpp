#include <iostream>
using namespace std;


class Patient{
    
    public:
        string name;
        int priority;
        string emergencyCondition;
        string arrivalOrder;
        Patient* next;
        Patient(string name,int priority,string emergencyCondition,string arrivalOrder){
            this->name = name;
            this->priority = priority;
            this->emergencyCondition = emergencyCondition;
            this->arrivalOrder = arrivalOrder;
        }

};
class Queue{
    Patient* front;
    Patient* rear;
    public:
        Queue(){
            front = NULL;
            rear = NULL;
        }
        
            void enqueue(string name, int priority, string emergencyCondition, string arrivalOrder) {
                Patient* newPatient = new Patient(name, priority, emergencyCondition, arrivalOrder);
                
                if (front == NULL) {
                    front = rear = newPatient;
                    return;
                }
                
                if (newPatient->priority < front->priority) {
                    newPatient->next = front;
                    front = newPatient;
                    return;
                }
                if(newPatient->priority==front->priority){
                    newPatient->next=front->next;
                    front->next=newPatient;
                    return;
                }
                if(newPatient->priority > front->priority){
                     
                    Patient* temp = front;
                    while (temp->next != NULL && temp->next->priority <= priority) {
                        temp = temp->next;
                    }
            
                    newPatient->next = temp->next;
                    temp->next = newPatient;
            
                    if (newPatient->next == NULL) {
                        rear = newPatient;
                    }
                }
               
            }
            
        void display(){
            Patient* temp = front;
            while(temp != NULL){
                cout << "Name: " << temp->name << ", Priority: " << temp->priority << ", Emergency Condition: " << temp->emergencyCondition << ", Arrival Order: " << temp->arrivalOrder << endl;
                temp = temp->next;
            }
        }
       

};

int assignPriority(string emergencyCondition){
    if(emergencyCondition=="Heart_Attack" || emergencyCondition=="Stroke"){
         return 1;
     }
     else if(emergencyCondition=="Severe_Burn" || emergencyCondition=="Fractured_Arm" || emergencyCondition=="Broken_Leg"){
         return 2;
     }
     else if(emergencyCondition=="Fever" || emergencyCondition=="Food_Poisoning"|| emergencyCondition=="Migraine"){
         return 3;
     }
     else if(emergencyCondition=="Small_Cuts" || emergencyCondition=="Mild_Cold"){
         return 4;
     }
     else{
         return 5;
     }
 }

void menu(Queue &q){
    
    bool RunMenu=true;
    while (RunMenu==true){
        cout<< "1. Add Patient" << endl;
        cout << "2. Display Patients" << endl;
        cout << "3. Exit" << endl;
        cout << "Enter your choice: ";
        int choice;
        cin >> choice;
        switch(choice){
            case 1:{
                string name,emergencyCondition,arrivalOrder;
                int priority;
                cout << "Enter Patient Name: ";
                cin >> name;
                cout << "Enter Emergency Condition: ";
                cin >> emergencyCondition;
                cout << "Enter Arrival Order: ";
                cin >> arrivalOrder;
                priority = assignPriority(emergencyCondition);
                if(priority==5){
                    cout << "No Emergency Condition found:" << endl;
                    
                }
                else{
                    q.enqueue(name,priority,emergencyCondition,arrivalOrder);
                }
               
                break;
            }
            case 2:{
                q.display();
                break;
            }
            case 3:{
                RunMenu=false;
                break;
            }
            default:{
                cout << "Invalid choice" << endl;
                break;
            }
        }

    }
   
}
int main(){

    Queue q;
    menu(q);

    return 0;
}
