#include <stdlib.h>
#include <string.h>

inline char *strdup(const char *s){
    char *result = (char *)malloc(sizeof(char) * (strlen(s)+1));
    strcpy(result, s);
    return result;
}
