#ifdef CSL_DEBUG
#define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_LOG(...) ((void)0)
#endif
#define port 8080
#define buffSize 1024
