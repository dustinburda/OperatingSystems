//
// Created by dustin on 8/20/23.
//

#ifndef PINTOS_UBUNTU_LOGGING_H
#define PINTOS_UBUNTU_LOGGING_H

#define NO_LOGGING         (0)
#define SYS_CALL_LOGGING   (1 << 0)
#define PROCESS_LOGGING    (1 << 1)
#define EXCEPTION_LOGGING  (1 << 2)
#define FILESYS_LOGGING    (1 << 3)
#define MY_LOGGING         (1 << 31)

#define LOG_LEVEL (MY_LOGGING)



//#define my_print1(level, a) if(level > PRINT) printf(a)
#define my_print1(level, a) if(level & LOG_LEVEL) printf(a)
#define my_print2(level, a,b) if(level & LOG_LEVEL) printf(a,b)
#define my_print3(level, a,b,c) if(level & LOG_LEVEL) printf(a,b,c)
#define my_print4(level, a,b,c,d) if(level & LOG_LEVEL) printf(a,b,c,d)
#define my_print5(level, a,b,c,d,e) if(level & LOG_LEVEL) printf(a,b,c,d,e)
#define my_print6(level, a,b,c,d,e,f) if(level & LOG_LEVEL) printf(a,b,c,d,e,f)
#define my_print7(level, a,b,c,d,e,f,g) if(level & LOG_LEVEL) printf(a,b,c,d,e,f,g)
#define my_print8(level, a,b,c,d,e,f,g,h) if(level & LOG_LEVEL) printf(a,b,c,d,e,f,g,h)
#define my_print9(level, a,b,c,d,e,f,g,h,i) if(level & LOG_LEVEL) printf(a,b,c,d,e,f,g,h,i)
//#else
//#define my_print1(a)
//#define my_print2(a,b)
//#define my_print3(a,b,c)
//#define my_print4(a,b,c,d)
//#define my_print5(a,b,c,d,e)
//#define my_print6(a,b,c,d,e,f)
//#define my_print7(a,b,c,d,e,f,g)
//#define my_print8(a,b,c,d,e,f,g,h)
//#define my_print9(a,b,c,d,e,f,g,h,i)
//#endif

#endif //PINTOS_UBUNTU_LOGGING_H
