#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#pragma pack(1)

#define INIT_SIZE 8

typedef struct {
  uint8_t mac[6];
} mac;

typedef struct {
  char *interface;
  uint8_t ap[6];
  uint8_t argc;
} args;

char* str(int size) {
	char* string = (char*)malloc(sizeof(char) * size);

	for (int i = 0; i < size; i++)
		string[i] = '\0';

	return string;
}

char** split(char *sentence, char separator) {
	char** tokens;
	int* lengths;
	int tokens_idx = 0;
	int token_idx = 0;
	int num_tokens = 1;

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator)
			(num_tokens)++;
	}

	lengths = (int*)malloc(sizeof(int) * (num_tokens));
	tokens = (char**)malloc(sizeof(char*) * (num_tokens));

	for (int i = 0; i < num_tokens; i++) {
		tokens[i] = str(INIT_SIZE);
		lengths[i] = INIT_SIZE;
	}

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator && strlen(tokens[tokens_idx]) != 0) {
			token_idx = 0;
			tokens_idx++;
		}
		else if (sentence[i] == separator && strlen(tokens[tokens_idx]) == 0){
			continue;
		}
		else {
			/* Memory reallocation, If  array is full. */

			if (strlen(tokens[tokens_idx]) == lengths[tokens_idx] - 1) {
				tokens[tokens_idx] = realloc(tokens[tokens_idx], (lengths[tokens_idx] * sizeof(char)) << 1);

				for (int j = lengths[tokens_idx]; j < lengths[tokens_idx] << 1; j++)
					tokens[tokens_idx][j] = '\0';

				lengths[tokens_idx] <<= 1;
			}

			tokens[tokens_idx][token_idx] = sentence[i];
			token_idx++;
		}
	}

	return tokens;
}


void usage() {
	printf("syntax : signal-strength <interface> <ap mac>\n");
	printf("sample : signal-strength mon0 00:11:22:33:44:55\n");
}

int compareMac(uint8_t *mac1, uint8_t *mac2) {
  for (int i = 0; i < 6; i++) {
    if (mac1[i] != mac2[i])
      return 0;
  }

  return 1;
}

void pushGraph(int signal) {
  static int graph[50][20] = { 0 };
  for (int i = 49; i > 0; i--) {
    for (int j = 0; j < 20; j++) {
      graph[i][j] = graph[i - 1][j];
    }
  }

  for (int i = 0; i < 20; i++) {
    graph[0][i] = 0;
  }

  signal = abs(signal);

  int idx = signal / 5;

  graph[0][idx] = 1;

  for (int j = 0; j < 20; j++) {
    printf("-%d ", j * 5);
    for (int i = 0; i < 50; i++) {
      if (graph[i][j] == 1) {
        printf("*");
      }
      else {
        printf(" ");
      }
    }
    printf("\n");
  }
}

int main(int argc, char* argv[]) {
  if (argc < 3 || argc > 4) {
		usage();
		return -1;
	}

  pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, NULL);
  if (handle == NULL) {
      printf("failed to open %s\n", argv[1]);
      return 0;
  }

  mac target;
  for(int i = 0; i < 6; i++) target.mac[i] = strtol(argv[2] + i * 3, NULL, 16);
  


  system("clear");
  while(1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    uint16_t headerLength = (packet[3] << 8) + packet[2];
    uint16_t type = (packet[headerLength] << 8) + packet[headerLength + 1];
    if (type == 0x8000) {
      mac ta;
      for (int i = 0; i < 6; i++) {
        ta.mac[i] = packet[headerLength + 10 + i];
      }
      if (!compareMac(ta.mac, target.mac)) {
        continue;
      }
      int8_t signal = packet[headerLength - 2];
      system("clear");
      printf("signal : %d\n\n", signal);
      pushGraph(signal);

    }
  }

  return 0;
}
