#include <iostream>
#include <string>
using namespace std;

class Node {
    public:
        string description;
        int id;
        int priority;
        Node *next;

        Node(string description, int id, int priority) {
            this->description = description;
            this->id = id;
            this->priority = priority;
            this->next = NULL;
        }
};

class List {
    public:
        Node *head;
        List() {
            head = NULL;
        }

        void adddeNewTask(string description, int id, int priority) {
            Node *newNode = new Node(description, id, priority);
            if (head == NULL || head->priority > priority) {
                newNode->next = head;
                head = newNode;
            } else {
                Node *temp = head;
                while (temp->next != NULL && temp->next->priority <= priority) {
                    temp = temp->next;
                }
                newNode->next = temp->next;
                temp->next = newNode;
            }
        }

        void deleteTask(int id) {
            if (head == NULL) {
                cout << "List is empty" << endl;
            } else {
                Node *temp = head;
                Node *prev = NULL;
                while (temp != NULL) {
                    if (temp->id == id) {
                        if (prev == NULL) {
                            head = temp->next;
                        } else {
                            prev->next = temp->next;
                        }
                        delete temp;
                        return;
                    }
                    prev = temp;
                    temp = temp->next;
                }
                cout << "ID not found" << endl;
            }
        }

        void deleteHighestPriority() {
            if (head == NULL) {
                cout << "List is empty" << endl;
            } else {
                Node *temp = head;
                head = head->next;
                delete temp;
                cout << "Highest priority task deleted" << endl;
            }
        }

        void viewTasks() {
            if (head == NULL) {
                cout << "List is empty" << endl;
            } else {
                Node *temp = head;
                while (temp != NULL) {
                    cout << "Description: " << temp->description << "   ID: " << temp->id << "     Priority: " << temp->priority << endl;
                    temp = temp->next;
                }
            }
        }
};

void myMenu() {
    List list;
    while (true) {
        cout << "1. Add description" << endl;
        cout << "2. Delete description" << endl;
        cout << "3. View description" << endl;
        cout << "4. Delete highest priority task" << endl;
        cout << "5. Exit" << endl;
        cout << "Enter your choice: ";
        int choice;
        cin >> choice;
        int id;
        int priority;
        string description;
        switch (choice) {
            case 1:
                cout << "Enter id: ";
                cin >> id;
                cout << "Enter priority: ";
                cin >> priority;
                cout << "Enter description: ";
                cin.ignore(); // 
                getline(cin, description); 
                list.adddeNewTask(description, id, priority);
                break;
            case 2:
                cout << "Enter id: ";
                cin >> id;
                list.deleteTask(id);
                break; 
            case 3:
                list.viewTasks();
                break;
            case 4:
                list.deleteHighestPriority();
                break;
            case 5:
                return; // Exit the function to end the program
            default:
                cout << "Invalid choice" << endl;
        }
    }
}

int main() {
    myMenu();
    return 0;
}