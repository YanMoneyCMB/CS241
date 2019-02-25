#include "dispatch.h"
#include <pcap.h>
#include "analysis.h"


#include <pthread.h>
#include <unistd.h>

//Number of threads is two due to a recommendation in the coursework specification
// (VM runs with only 1 processor core)
#define no_threads 2

//Node structure to implement a queue of packets
struct packet_node{
  struct pcap_pkthdr *header;
  unsigned char *packet;
  int verbose;
  struct packet_node *next;
};

//Global variables of the queue
struct packet_node *front = NULL;
struct packet_node *end = NULL;
int size = 0;

//Array of threads
pthread_t threads[no_threads];

//Create mutex lock and condition
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

//Condition to indicate whether program should be running
int run = 0;


//As next two functions operate onto the structure of the queue, mutex lock
//has to be activated for the whole function
void *dequeue (void *arg){
  while(run == 1){
    pthread_mutex_lock(&lock);
//Signal threads to wait until packets are received
    while(size<1){
      pthread_cond_wait(&condition,&lock);
    }
//For threads not to get stuck in the loop on termination of the program
    if(run){

      struct packet_node *t;
      t = front;
      struct packet_node *current = (struct packet_node *) malloc(sizeof(struct packet_node));
      *current = *front;

      if(front == end){
        front = NULL;
        end = NULL;
      }else{
        front = front->next;
      }
      size--;
      free(t);
      pthread_mutex_unlock(&lock);
      analyse(current->header,current->packet,current->verbose);

      free(current);
    }else{
      pthread_mutex_unlock(&lock);
    }
  }
  return (void *) arg;
}

void enqueue(struct packet_node *p){
  pthread_mutex_lock(&lock);

  if(front == NULL){
    front = p;
    end = p;
  }else{
    end->next = p;
    end = p;
  }
  size++;
//signal to unblock one of the threads to dequue
  pthread_cond_signal(&condition);
  pthread_mutex_unlock(&lock);
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
//If the function is called for the first time, create threads
  if(run == 0){
      run = 1;
      int i;
      for(i=0;i<no_threads;i++){
        if(pthread_create(&threads[i], NULL, &dequeue,(void *) NULL)){
          fprintf(stderr, "\n Error creating threads.\n");
        };
      }
  }
//Construct a new packet node to enqueue
struct packet_node *new_packet=malloc(sizeof(struct packet_node));
new_packet->header = (struct pcap_pkthdr *) header;
new_packet->packet = (unsigned char *) packet;
new_packet->verbose = verbose;
new_packet->next = NULL;

enqueue(new_packet);
}
//Function to unlock all threads, join them, and destroy all the locks 
void cleanMemory(){
  pthread_mutex_lock(&lock);
  run = 0;
  size = 1;
  pthread_cond_broadcast(&condition);
  pthread_mutex_unlock(&lock);
  pthread_mutex_destroy(&lock);
  pthread_cond_destroy(&condition);
  int i;
  for(i=0;i<no_threads;i++){
    pthread_join(threads[i],NULL);
  }
}
