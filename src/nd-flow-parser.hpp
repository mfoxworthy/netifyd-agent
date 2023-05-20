/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_ND_FLOW_PARSER_HPP_INCLUDED
# define YY_YY_ND_FLOW_PARSER_HPP_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 156 "nd-flow-parser.ypp"

typedef void* yyscan_t;

#line 53 "nd-flow-parser.hpp"

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    FLOW_IP_PROTO = 258,           /* FLOW_IP_PROTO  */
    FLOW_IP_VERSION = 259,         /* FLOW_IP_VERSION  */
    FLOW_IP_NAT = 260,             /* FLOW_IP_NAT  */
    FLOW_VLAN_ID = 261,            /* FLOW_VLAN_ID  */
    FLOW_OTHER_TYPE = 262,         /* FLOW_OTHER_TYPE  */
    FLOW_LOCAL_MAC = 263,          /* FLOW_LOCAL_MAC  */
    FLOW_OTHER_MAC = 264,          /* FLOW_OTHER_MAC  */
    FLOW_LOCAL_IP = 265,           /* FLOW_LOCAL_IP  */
    FLOW_OTHER_IP = 266,           /* FLOW_OTHER_IP  */
    FLOW_LOCAL_PORT = 267,         /* FLOW_LOCAL_PORT  */
    FLOW_OTHER_PORT = 268,         /* FLOW_OTHER_PORT  */
    FLOW_TUNNEL_TYPE = 269,        /* FLOW_TUNNEL_TYPE  */
    FLOW_DETECTION_GUESSED = 270,  /* FLOW_DETECTION_GUESSED  */
    FLOW_DETECTION_UPDATED = 271,  /* FLOW_DETECTION_UPDATED  */
    FLOW_CATEGORY = 272,           /* FLOW_CATEGORY  */
    FLOW_RISKS = 273,              /* FLOW_RISKS  */
    FLOW_NDPI_RISK_SCORE = 274,    /* FLOW_NDPI_RISK_SCORE  */
    FLOW_NDPI_RISK_SCORE_CLIENT = 275, /* FLOW_NDPI_RISK_SCORE_CLIENT  */
    FLOW_NDPI_RISK_SCORE_SERVER = 276, /* FLOW_NDPI_RISK_SCORE_SERVER  */
    FLOW_DOMAIN_CATEGORY = 277,    /* FLOW_DOMAIN_CATEGORY  */
    FLOW_APPLICATION = 278,        /* FLOW_APPLICATION  */
    FLOW_APPLICATION_CATEGORY = 279, /* FLOW_APPLICATION_CATEGORY  */
    FLOW_PROTOCOL = 280,           /* FLOW_PROTOCOL  */
    FLOW_PROTOCOL_CATEGORY = 281,  /* FLOW_PROTOCOL_CATEGORY  */
    FLOW_DETECTED_HOSTNAME = 282,  /* FLOW_DETECTED_HOSTNAME  */
    FLOW_SSL_VERSION = 283,        /* FLOW_SSL_VERSION  */
    FLOW_SSL_CIPHER = 284,         /* FLOW_SSL_CIPHER  */
    FLOW_ORIGIN = 285,             /* FLOW_ORIGIN  */
    FLOW_CT_MARK = 286,            /* FLOW_CT_MARK  */
    FLOW_OTHER_UNKNOWN = 287,      /* FLOW_OTHER_UNKNOWN  */
    FLOW_OTHER_UNSUPPORTED = 288,  /* FLOW_OTHER_UNSUPPORTED  */
    FLOW_OTHER_LOCAL = 289,        /* FLOW_OTHER_LOCAL  */
    FLOW_OTHER_MULTICAST = 290,    /* FLOW_OTHER_MULTICAST  */
    FLOW_OTHER_BROADCAST = 291,    /* FLOW_OTHER_BROADCAST  */
    FLOW_OTHER_REMOTE = 292,       /* FLOW_OTHER_REMOTE  */
    FLOW_OTHER_ERROR = 293,        /* FLOW_OTHER_ERROR  */
    FLOW_ORIGIN_LOCAL = 294,       /* FLOW_ORIGIN_LOCAL  */
    FLOW_ORIGIN_OTHER = 295,       /* FLOW_ORIGIN_OTHER  */
    FLOW_ORIGIN_UNKNOWN = 296,     /* FLOW_ORIGIN_UNKNOWN  */
    FLOW_TUNNEL_NONE = 297,        /* FLOW_TUNNEL_NONE  */
    FLOW_TUNNEL_GTP = 298,         /* FLOW_TUNNEL_GTP  */
    CMP_EQUAL = 299,               /* CMP_EQUAL  */
    CMP_NOTEQUAL = 300,            /* CMP_NOTEQUAL  */
    CMP_GTHANEQUAL = 301,          /* CMP_GTHANEQUAL  */
    CMP_LTHANEQUAL = 302,          /* CMP_LTHANEQUAL  */
    BOOL_AND = 303,                /* BOOL_AND  */
    BOOL_OR = 304,                 /* BOOL_OR  */
    VALUE_ADDR_IPMASK = 305,       /* VALUE_ADDR_IPMASK  */
    VALUE_TRUE = 306,              /* VALUE_TRUE  */
    VALUE_FALSE = 307,             /* VALUE_FALSE  */
    VALUE_ADDR_MAC = 308,          /* VALUE_ADDR_MAC  */
    VALUE_ADDR_IPV4 = 309,         /* VALUE_ADDR_IPV4  */
    VALUE_ADDR_IPV6 = 310,         /* VALUE_ADDR_IPV6  */
    VALUE_NAME = 311,              /* VALUE_NAME  */
    VALUE_REGEX = 312,             /* VALUE_REGEX  */
    VALUE_NUMBER = 313             /* VALUE_NUMBER  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define FLOW_IP_PROTO 258
#define FLOW_IP_VERSION 259
#define FLOW_IP_NAT 260
#define FLOW_VLAN_ID 261
#define FLOW_OTHER_TYPE 262
#define FLOW_LOCAL_MAC 263
#define FLOW_OTHER_MAC 264
#define FLOW_LOCAL_IP 265
#define FLOW_OTHER_IP 266
#define FLOW_LOCAL_PORT 267
#define FLOW_OTHER_PORT 268
#define FLOW_TUNNEL_TYPE 269
#define FLOW_DETECTION_GUESSED 270
#define FLOW_DETECTION_UPDATED 271
#define FLOW_CATEGORY 272
#define FLOW_RISKS 273
#define FLOW_NDPI_RISK_SCORE 274
#define FLOW_NDPI_RISK_SCORE_CLIENT 275
#define FLOW_NDPI_RISK_SCORE_SERVER 276
#define FLOW_DOMAIN_CATEGORY 277
#define FLOW_APPLICATION 278
#define FLOW_APPLICATION_CATEGORY 279
#define FLOW_PROTOCOL 280
#define FLOW_PROTOCOL_CATEGORY 281
#define FLOW_DETECTED_HOSTNAME 282
#define FLOW_SSL_VERSION 283
#define FLOW_SSL_CIPHER 284
#define FLOW_ORIGIN 285
#define FLOW_CT_MARK 286
#define FLOW_OTHER_UNKNOWN 287
#define FLOW_OTHER_UNSUPPORTED 288
#define FLOW_OTHER_LOCAL 289
#define FLOW_OTHER_MULTICAST 290
#define FLOW_OTHER_BROADCAST 291
#define FLOW_OTHER_REMOTE 292
#define FLOW_OTHER_ERROR 293
#define FLOW_ORIGIN_LOCAL 294
#define FLOW_ORIGIN_OTHER 295
#define FLOW_ORIGIN_UNKNOWN 296
#define FLOW_TUNNEL_NONE 297
#define FLOW_TUNNEL_GTP 298
#define CMP_EQUAL 299
#define CMP_NOTEQUAL 300
#define CMP_GTHANEQUAL 301
#define CMP_LTHANEQUAL 302
#define BOOL_AND 303
#define BOOL_OR 304
#define VALUE_ADDR_IPMASK 305
#define VALUE_TRUE 306
#define VALUE_FALSE 307
#define VALUE_ADDR_MAC 308
#define VALUE_ADDR_IPV4 309
#define VALUE_ADDR_IPV6 310
#define VALUE_NAME 311
#define VALUE_REGEX 312
#define VALUE_NUMBER 313

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 163 "nd-flow-parser.ypp"

    char string[_NDFP_MAX_NAMELEN];

    bool bool_number;
    unsigned short us_number;
    unsigned long ul_number;

    bool bool_result;

#line 199 "nd-flow-parser.hpp"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif




int yyparse (yyscan_t scanner);


#endif /* !YY_YY_ND_FLOW_PARSER_HPP_INCLUDED  */
