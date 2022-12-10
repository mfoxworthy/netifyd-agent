/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 2

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* "%code top" blocks.  */
#line 5 "nd-flow-criteria.tab.yy" /* yacc.c:316  */

// Netify Agent
// Copyright (C) 2015-2022 eGloo Incorporated <http://www.egloo.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <cstring>
#include <map>
#include <list>
#include <vector>
#include <set>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <regex>
#include <mutex>
#include <bitset>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <errno.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#include "nd-apps.h"
#include "nd-category.h"
#include "nd-protos.h"
#include "nd-risks.h"
#include "nd-flow.h"

#include "nd-flow-parser.h"
#include "nd-flow-criteria.tab.hh"

extern "C" {
    #include "nd-flow-criteria.h"

    void yyerror(YYLTYPE *yyllocp, yyscan_t scanner, const char *message);
}

void yyerror(YYLTYPE *yyllocp, yyscan_t scanner, const char *message)
{
    throw string(message);
}

extern ndCategories *nd_categories;
extern ndDomains *nd_domains;

#line 157 "nd-flow-criteria.tab.cc" /* yacc.c:316  */



/* Copy the first part of user declarations.  */

#line 163 "nd-flow-criteria.tab.cc" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_YY_ND_FLOW_CRITERIA_TAB_HH_INCLUDED
# define YY_YY_ND_FLOW_CRITERIA_TAB_HH_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 99 "nd-flow-criteria.tab.yy" /* yacc.c:355  */

typedef void* yyscan_t;

#line 197 "nd-flow-criteria.tab.cc" /* yacc.c:355  */

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    FLOW_IP_PROTO = 258,
    FLOW_IP_VERSION = 259,
    FLOW_IP_NAT = 260,
    FLOW_VLAN_ID = 261,
    FLOW_OTHER_TYPE = 262,
    FLOW_LOCAL_MAC = 263,
    FLOW_OTHER_MAC = 264,
    FLOW_LOCAL_IP = 265,
    FLOW_OTHER_IP = 266,
    FLOW_LOCAL_PORT = 267,
    FLOW_OTHER_PORT = 268,
    FLOW_TUNNEL_TYPE = 269,
    FLOW_DETECTION_GUESSED = 270,
    FLOW_CATEGORY = 271,
    FLOW_RISKS = 272,
    FLOW_NDPI_RISK_SCORE = 273,
    FLOW_NDPI_RISK_SCORE_CLIENT = 274,
    FLOW_NDPI_RISK_SCORE_SERVER = 275,
    FLOW_DOMAIN_CATEGORY = 276,
    FLOW_APPLICATION = 277,
    FLOW_APPLICATION_CATEGORY = 278,
    FLOW_PROTOCOL = 279,
    FLOW_PROTOCOL_CATEGORY = 280,
    FLOW_DETECTED_HOSTNAME = 281,
    FLOW_SSL_VERSION = 282,
    FLOW_SSL_CIPHER = 283,
    FLOW_ORIGIN = 284,
    FLOW_CT_MARK = 285,
    FLOW_OTHER_UNKNOWN = 286,
    FLOW_OTHER_UNSUPPORTED = 287,
    FLOW_OTHER_LOCAL = 288,
    FLOW_OTHER_MULTICAST = 289,
    FLOW_OTHER_BROADCAST = 290,
    FLOW_OTHER_REMOTE = 291,
    FLOW_OTHER_ERROR = 292,
    FLOW_ORIGIN_LOCAL = 293,
    FLOW_ORIGIN_OTHER = 294,
    FLOW_ORIGIN_UNKNOWN = 295,
    FLOW_TUNNEL_NONE = 296,
    FLOW_TUNNEL_GTP = 297,
    CMP_EQUAL = 298,
    CMP_NOTEQUAL = 299,
    CMP_GTHANEQUAL = 300,
    CMP_LTHANEQUAL = 301,
    BOOL_AND = 302,
    BOOL_OR = 303,
    VALUE_ADDR_IPMASK = 304,
    VALUE_TRUE = 305,
    VALUE_FALSE = 306,
    VALUE_ADDR_MAC = 307,
    VALUE_ADDR_IPV4 = 308,
    VALUE_ADDR_IPV6 = 309,
    VALUE_NAME = 310,
    VALUE_REGEX = 311,
    VALUE_NUMBER = 312
  };
#endif
/* Tokens.  */
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
#define FLOW_CATEGORY 271
#define FLOW_RISKS 272
#define FLOW_NDPI_RISK_SCORE 273
#define FLOW_NDPI_RISK_SCORE_CLIENT 274
#define FLOW_NDPI_RISK_SCORE_SERVER 275
#define FLOW_DOMAIN_CATEGORY 276
#define FLOW_APPLICATION 277
#define FLOW_APPLICATION_CATEGORY 278
#define FLOW_PROTOCOL 279
#define FLOW_PROTOCOL_CATEGORY 280
#define FLOW_DETECTED_HOSTNAME 281
#define FLOW_SSL_VERSION 282
#define FLOW_SSL_CIPHER 283
#define FLOW_ORIGIN 284
#define FLOW_CT_MARK 285
#define FLOW_OTHER_UNKNOWN 286
#define FLOW_OTHER_UNSUPPORTED 287
#define FLOW_OTHER_LOCAL 288
#define FLOW_OTHER_MULTICAST 289
#define FLOW_OTHER_BROADCAST 290
#define FLOW_OTHER_REMOTE 291
#define FLOW_OTHER_ERROR 292
#define FLOW_ORIGIN_LOCAL 293
#define FLOW_ORIGIN_OTHER 294
#define FLOW_ORIGIN_UNKNOWN 295
#define FLOW_TUNNEL_NONE 296
#define FLOW_TUNNEL_GTP 297
#define CMP_EQUAL 298
#define CMP_NOTEQUAL 299
#define CMP_GTHANEQUAL 300
#define CMP_LTHANEQUAL 301
#define BOOL_AND 302
#define BOOL_OR 303
#define VALUE_ADDR_IPMASK 304
#define VALUE_TRUE 305
#define VALUE_FALSE 306
#define VALUE_ADDR_MAC 307
#define VALUE_ADDR_IPV4 308
#define VALUE_ADDR_IPV6 309
#define VALUE_NAME 310
#define VALUE_REGEX 311
#define VALUE_NUMBER 312

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 106 "nd-flow-criteria.tab.yy" /* yacc.c:355  */

    char string[_NDFP_MAX_NAMELEN];

    bool bool_number;
    unsigned short us_number;
    unsigned long ul_number;

    bool bool_result;

#line 333 "nd-flow-criteria.tab.cc" /* yacc.c:355  */
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

#endif /* !YY_YY_ND_FLOW_CRITERIA_TAB_HH_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 363 "nd-flow-criteria.tab.cc" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
             && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE) + sizeof (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   307

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  64
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  39
/* YYNRULES -- Number of rules.  */
#define YYNRULES  196
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  308

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   312

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    61,     2,     2,     2,     2,     2,     2,
      59,    60,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    58,
      63,     2,    62,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   162,   162,   164,   168,   169,   170,   171,   172,   173,
     174,   175,   176,   177,   178,   179,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,   190,   191,   192,   193,
     194,   195,   196,   200,   204,   208,   213,   217,   221,   225,
     229,   233,   237,   244,   248,   255,   259,   263,   267,   271,
     275,   282,   286,   290,   294,   298,   302,   306,   310,   317,
     323,   329,   373,   420,   421,   422,   423,   424,   425,   426,
     430,   436,   445,   451,   460,   466,   475,   481,   490,   491,
     495,   499,   503,   507,   511,   515,   519,   523,   530,   534,
     538,   542,   546,   550,   554,   558,   565,   571,   577,   596,
     618,   619,   622,   626,   632,   640,   648,   656,   667,   673,
     681,   682,   685,   694,   706,   731,   759,   784,   812,   816,
     820,   838,   860,   864,   868,   872,   876,   880,   884,   888,
     895,   899,   903,   907,   911,   915,   919,   923,   930,   934,
     938,   942,   946,   950,   954,   958,   965,   981,  1000,  1016,
    1035,  1041,  1047,  1048,  1051,  1057,  1066,  1085,  1106,  1123,
    1143,  1150,  1157,  1175,  1193,  1230,  1239,  1247,  1255,  1263,
    1271,  1279,  1287,  1295,  1306,  1310,  1314,  1318,  1322,  1326,
    1330,  1334,  1341,  1345,  1349,  1353,  1357,  1361,  1365,  1369,
    1376,  1380,  1384,  1388,  1395,  1396,  1397
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "FLOW_IP_PROTO", "FLOW_IP_VERSION",
  "FLOW_IP_NAT", "FLOW_VLAN_ID", "FLOW_OTHER_TYPE", "FLOW_LOCAL_MAC",
  "FLOW_OTHER_MAC", "FLOW_LOCAL_IP", "FLOW_OTHER_IP", "FLOW_LOCAL_PORT",
  "FLOW_OTHER_PORT", "FLOW_TUNNEL_TYPE", "FLOW_DETECTION_GUESSED",
  "FLOW_CATEGORY", "FLOW_RISKS", "FLOW_NDPI_RISK_SCORE",
  "FLOW_NDPI_RISK_SCORE_CLIENT", "FLOW_NDPI_RISK_SCORE_SERVER",
  "FLOW_DOMAIN_CATEGORY", "FLOW_APPLICATION", "FLOW_APPLICATION_CATEGORY",
  "FLOW_PROTOCOL", "FLOW_PROTOCOL_CATEGORY", "FLOW_DETECTED_HOSTNAME",
  "FLOW_SSL_VERSION", "FLOW_SSL_CIPHER", "FLOW_ORIGIN", "FLOW_CT_MARK",
  "FLOW_OTHER_UNKNOWN", "FLOW_OTHER_UNSUPPORTED", "FLOW_OTHER_LOCAL",
  "FLOW_OTHER_MULTICAST", "FLOW_OTHER_BROADCAST", "FLOW_OTHER_REMOTE",
  "FLOW_OTHER_ERROR", "FLOW_ORIGIN_LOCAL", "FLOW_ORIGIN_OTHER",
  "FLOW_ORIGIN_UNKNOWN", "FLOW_TUNNEL_NONE", "FLOW_TUNNEL_GTP",
  "CMP_EQUAL", "CMP_NOTEQUAL", "CMP_GTHANEQUAL", "CMP_LTHANEQUAL",
  "BOOL_AND", "BOOL_OR", "VALUE_ADDR_IPMASK", "VALUE_TRUE", "VALUE_FALSE",
  "VALUE_ADDR_MAC", "VALUE_ADDR_IPV4", "VALUE_ADDR_IPV6", "VALUE_NAME",
  "VALUE_REGEX", "VALUE_NUMBER", "';'", "'('", "')'", "'!'", "'>'", "'<'",
  "$accept", "exprs", "expr", "expr_ip_proto", "expr_ip_version",
  "expr_ip_nat", "expr_vlan_id", "expr_other_type", "value_other_type",
  "expr_local_mac", "expr_other_mac", "expr_local_ip", "expr_other_ip",
  "value_addr_ip", "expr_local_port", "expr_other_port",
  "expr_tunnel_type", "value_tunnel_type", "expr_detection_guessed",
  "expr_app", "expr_app_id", "expr_app_name", "expr_category",
  "expr_risks", "expr_ndpi_risk_score", "expr_ndpi_risk_score_client",
  "expr_ndpi_risk_score_server", "expr_app_category",
  "expr_domain_category", "expr_proto", "expr_proto_id", "expr_proto_name",
  "expr_proto_category", "expr_detected_hostname", "expr_fwmark",
  "expr_ssl_version", "expr_ssl_cipher", "expr_origin",
  "value_origin_type", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,    59,    40,
      41,    33,    62,    60
};
# endif

#define YYPACT_NINF -42

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-42)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -42,     1,   -42,    53,   -41,    74,    57,    78,   103,   112,
     116,   128,    61,    66,   152,   154,   156,   158,    87,    91,
      95,   160,   162,   164,   166,   168,   170,    99,   120,   172,
     124,    29,    65,   126,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,     4,    12,    24,    51,
      69,   136,   177,   179,    63,   167,   180,   181,   182,   183,
     184,   186,   144,   144,    34,    96,   190,   192,   169,   169,
     169,   169,   188,   189,   191,   193,   194,   195,   196,   197,
     198,   199,   200,   201,   178,   178,   174,   176,   130,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     227,   228,    70,   133,   229,   230,   134,   137,   231,   232,
     173,   175,   233,   234,   235,   236,   237,   238,   239,   240,
     241,   242,   243,   244,    27,    27,   245,   246,   247,   248,
     249,   250,    16,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,    29,    29,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   185,   185
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    35,     0,    45,    51,    59,     0,     0,
       0,     0,    80,    88,    96,   102,     0,   118,   122,   130,
     138,     0,   108,     0,   150,     0,   160,   174,   182,   190,
     166,     0,     0,     0,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    22,   110,   111,
      17,    18,    19,    20,    21,    23,    24,    25,   152,   153,
      26,    27,    31,    28,    29,    30,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    36,    46,    52,    60,    81,    89,    97,
     103,   119,   123,   131,   139,   109,   151,   161,   175,   183,
     191,   167,     0,     0,     3,    37,    38,    39,    40,    41,
      42,    43,    44,    47,    48,    49,    50,    53,    54,    55,
      56,    57,    58,    63,    64,    65,    66,    67,    68,    69,
      61,    62,    70,    71,    72,    73,    78,    79,    74,    75,
      76,    77,    82,    83,    84,    85,    86,    87,    90,    91,
      92,    93,    94,    95,   100,   101,    98,    99,   104,   105,
     106,   107,   116,   117,   120,   121,   124,   125,   126,   127,
     128,   129,   132,   133,   134,   135,   136,   137,   140,   141,
     142,   143,   144,   145,   148,   149,   114,   112,   115,   113,
     146,   147,   156,   154,   157,   155,   158,   159,   162,   164,
     163,   165,   176,   177,   178,   179,   180,   181,   184,   185,
     186,   187,   188,   189,   194,   195,   196,   192,   193,   168,
     169,   170,   171,   172,   173,    34,    33,    32
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -42,   -42,   -31,   -42,   -42,   -42,   -42,   -42,   138,   -42,
     -42,   -42,   -42,   -16,   -42,   -42,   -42,   142,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,
     -42,   -42,   -42,   -42,   -42,   -42,   -42,   -42,    80
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    33,    34,    35,    36,    37,    38,   210,    39,
      40,    41,    42,   218,    43,    44,    45,   236,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,   297
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint16 yytable[] =
{
     162,     2,    72,    73,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,   185,    32,   182,   183,   294,   295,   296,   163,   186,
     164,   165,   166,   219,   220,   221,   305,   167,   168,   169,
     170,   187,   171,   172,   173,   174,   212,   175,    31,   176,
      32,   177,   178,   179,   180,   181,    66,    67,    68,    69,
      76,    77,    78,    79,    92,    93,    94,    95,   188,    98,
      99,   100,   101,   193,   194,    70,    71,    74,    75,    80,
      81,    82,    83,    96,    97,   266,   189,   267,   102,   103,
     112,   113,   114,   115,   118,   119,   120,   121,   124,   125,
     126,   127,   142,   143,   144,   145,    84,    85,   213,   116,
     117,   306,   307,   122,   123,    86,    87,   128,   129,    88,
      89,   146,   147,   148,   149,   150,   151,   156,   157,   158,
     159,    90,    91,   182,   183,   203,   204,   205,   206,   207,
     208,   209,   152,   153,   184,   242,   160,   161,   268,   272,
     269,   273,   274,   190,   275,   104,   105,   106,   107,   108,
     109,   110,   111,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   154,   155,   195,   196,   234,
     235,   211,   216,   217,   238,   239,   240,   241,   278,   279,
     280,   281,   182,   183,   191,   298,   192,   197,   198,   199,
     200,   201,   214,   202,   215,   222,   223,   237,   224,     0,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   243,
     244,   245,     0,     0,   246,   247,   248,   249,   250,   251,
     252,   253,   254,   255,   256,   257,   258,   259,   260,   261,
     262,   263,   264,   265,   270,   271,   276,   277,     0,     0,
     282,   283,   284,   285,   286,   287,   288,   289,   290,   291,
     292,   293,   299,   300,   301,   302,   303,   304
};

static const yytype_int16 yycheck[] =
{
      31,     0,    43,    44,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      59,    57,    61,    47,    48,    38,    39,    40,     3,    57,
       5,     6,     7,    89,    90,    91,    60,    12,    13,    14,
      15,    57,    17,    18,    19,    20,    52,    22,    59,    24,
      61,    26,    27,    28,    29,    30,    43,    44,    45,    46,
      43,    44,    45,    46,    43,    44,    45,    46,    57,    43,
      44,    45,    46,    50,    51,    62,    63,    43,    44,    62,
      63,    43,    44,    62,    63,    55,    57,    57,    62,    63,
      43,    44,    45,    46,    43,    44,    45,    46,    43,    44,
      45,    46,    43,    44,    45,    46,    43,    44,    52,    62,
      63,   182,   183,    62,    63,    43,    44,    62,    63,    43,
      44,    62,    63,    43,    44,    45,    46,    43,    44,    45,
      46,    43,    44,    47,    48,    31,    32,    33,    34,    35,
      36,    37,    62,    63,    58,    55,    62,    63,    55,    55,
      57,    57,    55,    57,    57,    43,    44,    43,    44,    43,
      44,    43,    44,    43,    44,    43,    44,    43,    44,    43,
      44,    43,    44,    43,    44,    43,    44,    50,    51,    41,
      42,    83,    53,    54,    50,    51,    50,    51,    55,    56,
      55,    56,    47,    48,    57,   155,    57,    57,    57,    57,
      57,    57,    52,    57,    52,    57,    57,   105,    57,    -1,
      57,    57,    57,    57,    57,    57,    57,    57,    57,    55,
      55,    55,    -1,    -1,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    57,    55,    55,    55,    55,    55,    55,    -1,    -1,
      57,    57,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    57,    57,    57,    57
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    65,     0,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    59,    61,    66,    67,    68,    69,    70,    71,    73,
      74,    75,    76,    78,    79,    80,    82,    83,    84,    85,
      86,    87,    88,    89,    90,    91,    92,    93,    94,    95,
      96,    97,    98,    99,   100,   101,    43,    44,    45,    46,
      62,    63,    43,    44,    43,    44,    43,    44,    45,    46,
      62,    63,    43,    44,    43,    44,    43,    44,    43,    44,
      43,    44,    43,    44,    45,    46,    62,    63,    43,    44,
      45,    46,    62,    63,    43,    44,    43,    44,    43,    44,
      43,    44,    43,    44,    45,    46,    62,    63,    43,    44,
      45,    46,    62,    63,    43,    44,    45,    46,    62,    63,
      43,    44,    43,    44,    43,    44,    43,    44,    43,    44,
      43,    44,    43,    44,    45,    46,    62,    63,    43,    44,
      45,    46,    62,    63,    43,    44,    43,    44,    45,    46,
      62,    63,    66,     3,     5,     6,     7,    12,    13,    14,
      15,    17,    18,    19,    20,    22,    24,    26,    27,    28,
      29,    30,    47,    48,    58,    57,    57,    57,    57,    57,
      57,    57,    57,    50,    51,    50,    51,    57,    57,    57,
      57,    57,    57,    31,    32,    33,    34,    35,    36,    37,
      72,    72,    52,    52,    52,    52,    53,    54,    77,    77,
      77,    77,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    41,    42,    81,    81,    50,    51,
      50,    51,    55,    55,    55,    55,    57,    57,    57,    57,
      57,    57,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    55,    55,    55,    57,    55,    57,
      55,    55,    55,    57,    55,    57,    55,    55,    55,    56,
      55,    56,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    38,    39,    40,   102,   102,    57,
      57,    57,    57,    57,    57,    60,    66,    66
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    64,    65,    65,    66,    66,    66,    66,    66,    66,
      66,    66,    66,    66,    66,    66,    66,    66,    66,    66,
      66,    66,    66,    66,    66,    66,    66,    66,    66,    66,
      66,    66,    66,    66,    66,    67,    67,    67,    67,    67,
      67,    67,    67,    68,    68,    69,    69,    69,    69,    69,
      69,    70,    70,    70,    70,    70,    70,    70,    70,    71,
      71,    71,    71,    72,    72,    72,    72,    72,    72,    72,
      73,    73,    74,    74,    75,    75,    76,    76,    77,    77,
      78,    78,    78,    78,    78,    78,    78,    78,    79,    79,
      79,    79,    79,    79,    79,    79,    80,    80,    80,    80,
      81,    81,    82,    82,    82,    82,    82,    82,    83,    83,
      83,    83,    84,    84,    85,    85,    86,    86,    87,    87,
      87,    87,    88,    88,    88,    88,    88,    88,    88,    88,
      89,    89,    89,    89,    89,    89,    89,    89,    90,    90,
      90,    90,    90,    90,    90,    90,    91,    91,    92,    92,
      93,    93,    93,    93,    94,    94,    95,    95,    96,    96,
      97,    97,    97,    97,    97,    97,    98,    98,    98,    98,
      98,    98,    98,    98,    99,    99,    99,    99,    99,    99,
      99,    99,   100,   100,   100,   100,   100,   100,   100,   100,
     101,   101,   101,   101,   102,   102,   102
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     3,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     3,     3,     3,     1,     2,     3,     3,     3,
       3,     3,     3,     3,     3,     1,     2,     3,     3,     3,
       3,     1,     2,     3,     3,     3,     3,     3,     3,     1,
       2,     3,     3,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     3,     3,     3,     3,     3,     3,     1,     1,
       1,     2,     3,     3,     3,     3,     3,     3,     1,     2,
       3,     3,     3,     3,     3,     3,     1,     2,     3,     3,
       1,     1,     1,     2,     3,     3,     3,     3,     1,     2,
       1,     1,     3,     3,     3,     3,     3,     3,     1,     2,
       3,     3,     1,     2,     3,     3,     3,     3,     3,     3,
       1,     2,     3,     3,     3,     3,     3,     3,     1,     2,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       1,     2,     1,     1,     3,     3,     3,     3,     3,     3,
       1,     2,     3,     3,     3,     3,     1,     2,     3,     3,
       3,     3,     3,     3,     1,     2,     3,     3,     3,     3,
       3,     3,     1,     2,     3,     3,     3,     3,     3,     3,
       1,     2,     3,     3,     1,     1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (&yylloc, scanner, YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static unsigned
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  unsigned res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
 }

#  define YY_LOCATION_PRINT(File, Loc)          \
  yy_location_print_ (File, &(Loc))

# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, Location, scanner); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, yyscan_t scanner)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (yylocationp);
  YYUSE (scanner);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, yyscan_t scanner)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  YY_LOCATION_PRINT (yyoutput, *yylocationp);
  YYFPRINTF (yyoutput, ": ");
  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp, scanner);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp, int yyrule, yyscan_t scanner)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                       , &(yylsp[(yyi + 1) - (yynrhs)])                       , scanner);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule, scanner); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, yyscan_t scanner)
{
  YYUSE (yyvaluep);
  YYUSE (yylocationp);
  YYUSE (scanner);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (yyscan_t scanner)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

/* Location data for the lookahead symbol.  */
static YYLTYPE yyloc_default
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
YYLTYPE yylloc = yyloc_default;

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.
       'yyls': related to locations.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    /* The location stack.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls;
    YYLTYPE *yylsp;

    /* The locations where the error started and ended.  */
    YYLTYPE yyerror_range[3];

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yylsp = yyls = yylsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  yylsp[0] = yylloc;
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yyls1, yysize * sizeof (*yylsp),
                    &yystacksize);

        yyls = yyls1;
        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, &yylloc, scanner);
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
  *++yylsp = yylloc;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location.  */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 32:
#line 196 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = ((yyvsp[-2].bool_result) || (yyvsp[0].bool_result)));
        _NDFP_debugf("OR (%d || %d == %d)\n", (yyvsp[-2].bool_result), (yyvsp[0].bool_result), (yyval.bool_result));
    }
#line 1786 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 33:
#line 200 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = ((yyvsp[-2].bool_result) && (yyvsp[0].bool_result)));
        _NDFP_debugf("AND (%d && %d == %d)\n", (yyvsp[-2].bool_result), (yyvsp[0].bool_result), (yyval.bool_result));
    }
#line 1795 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 34:
#line 204 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { _NDFP_result = ((yyval.bool_result) = (yyvsp[-1].bool_result)); }
#line 1801 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 35:
#line 208 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol != 0));
        _NDFP_debugf(
            "IP Protocol is non-zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1811 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 36:
#line 213 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol == 0));
        _NDFP_debugf("IP Protocol is zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1820 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 37:
#line 217 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol == (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1829 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 38:
#line 221 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol != (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1838 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 39:
#line 225 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol >= (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1847 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 40:
#line 229 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol <= (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1856 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 41:
#line 233 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol > (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1865 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 42:
#line 237 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol < (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1874 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 43:
#line 244 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_version == (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Version == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1883 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 44:
#line 248 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_version != (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Version != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1892 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 45:
#line 255 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == true));
        _NDFP_debugf("IP NAT is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1901 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 46:
#line 259 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == false));
        _NDFP_debugf("IP NAT is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1910 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 47:
#line 263 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == true));
        _NDFP_debugf("IP NAT == true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1919 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 48:
#line 267 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == false));
        _NDFP_debugf("IP NAT == false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1928 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 49:
#line 271 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() != true));
        _NDFP_debugf("IP NAT != true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1937 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 50:
#line 275 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() != false));
        _NDFP_debugf("IP NAT != false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1946 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 51:
#line 282 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id != 0));
        _NDFP_debugf("VLAN ID is non-zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1955 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 52:
#line 286 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id == 0));
        _NDFP_debugf("VLAN ID is zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1964 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 53:
#line 290 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id == (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1973 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 54:
#line 294 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id != (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1982 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 55:
#line 298 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id >= (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1991 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 56:
#line 302 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id <= (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2000 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 57:
#line 306 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id > (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2009 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 58:
#line 310 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id < (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2018 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 59:
#line 317 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->other_type != ndFlow::OTHER_UNKNOWN
        ));
        _NDFP_debugf("Other type known? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2029 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 60:
#line 323 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->other_type == ndFlow::OTHER_UNKNOWN
        ));
        _NDFP_debugf("Other type unknown? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2040 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 61:
#line 329 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        switch ((yyvsp[0].us_number)) {
        case _NDFP_OTHER_UNKNOWN:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_UNKNOWN
            );
            break;
        case _NDFP_OTHER_UNSUPPORTED:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_UNSUPPORTED
            );
            break;
        case _NDFP_OTHER_LOCAL:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_LOCAL
            );
            break;
        case _NDFP_OTHER_MULTICAST:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_MULTICAST
            );
            break;
        case _NDFP_OTHER_BROADCAST:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_BROADCAST
            );
            break;
        case _NDFP_OTHER_REMOTE:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_REMOTE
            );
            break;
        case _NDFP_OTHER_ERROR:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_ERROR
            );
            break;
        default:
            _NDFP_result = false;
        }

        (yyval.bool_result) = _NDFP_result;
        _NDFP_debugf("Other type == %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2089 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 62:
#line 373 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        switch ((yyvsp[0].us_number)) {
        case _NDFP_OTHER_UNKNOWN:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_UNKNOWN
            );
            break;
        case _NDFP_OTHER_UNSUPPORTED:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_UNSUPPORTED
            );
            break;
        case _NDFP_OTHER_LOCAL:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_LOCAL
            );
            break;
        case _NDFP_OTHER_MULTICAST:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_MULTICAST
            );
            break;
        case _NDFP_OTHER_BROADCAST:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_BROADCAST
            );
            break;
        case _NDFP_OTHER_REMOTE:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_REMOTE
            );
            break;
        case _NDFP_OTHER_ERROR:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_ERROR
            );
            break;
        default:
            _NDFP_result = false;
        }

        (yyval.bool_result) = _NDFP_result;
        _NDFP_debugf("Other type != %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2138 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 63:
#line 420 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2144 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 64:
#line 421 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2150 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 65:
#line 422 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2156 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 66:
#line 423 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2162 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 67:
#line 424 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2168 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 68:
#line 425 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2174 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 69:
#line 426 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2180 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 70:
#line 430 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_mac, (yyvsp[0].string), ND_STR_ETHALEN) == 0
        ));
        _NDFP_debugf("Local MAC == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2191 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 71:
#line 436 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_mac, (yyvsp[0].string), ND_STR_ETHALEN) != 0
        ));
        _NDFP_debugf("Local MAC != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2202 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 72:
#line 445 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_mac, (yyvsp[0].string), ND_STR_ETHALEN) == 0
        ));
        _NDFP_debugf("Other MAC == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2213 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 73:
#line 451 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_mac, (yyvsp[0].string), ND_STR_ETHALEN) != 0
        ));
        _NDFP_debugf("Other MAC != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2224 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 74:
#line 460 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) == 0
        ));
        _NDFP_debugf("Local IP == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2235 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 75:
#line 466 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) != 0
        ));
        _NDFP_debugf("Local IP != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2246 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 76:
#line 475 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) == 0
        ));
        _NDFP_debugf("Other IP == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2257 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 77:
#line 481 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) != 0
        ));
        _NDFP_debugf("Other IP != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2268 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 78:
#line 490 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { strncpy((yyval.string), (yyvsp[0].string), _NDFP_MAX_NAMELEN); }
#line 2274 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 79:
#line 491 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { strncpy((yyval.string), (yyvsp[0].string), _NDFP_MAX_NAMELEN); }
#line 2280 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 80:
#line 495 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port != 0));
        _NDFP_debugf("Local port is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2289 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 81:
#line 499 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port == 0));
        _NDFP_debugf("Local port is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2298 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 82:
#line 503 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port == (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2307 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 83:
#line 507 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port != (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2316 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 84:
#line 511 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port >= (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2325 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 85:
#line 515 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port <= (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2334 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 86:
#line 519 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port > (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2343 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 87:
#line 523 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port < (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2352 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 88:
#line 530 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port != 0));
        _NDFP_debugf("Other port is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2361 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 89:
#line 534 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port == 0));
        _NDFP_debugf("Other port is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2370 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 90:
#line 538 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port == (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2379 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 91:
#line 542 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port != (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2388 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 92:
#line 546 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port >= (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2397 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 93:
#line 550 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port <= (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2406 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 94:
#line 554 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port > (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2415 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 95:
#line 558 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port < (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2424 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 96:
#line 565 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->tunnel_type != ndFlow::TUNNEL_NONE
        ));
        _NDFP_debugf("Tunnel type set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2435 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 97:
#line 571 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->tunnel_type == ndFlow::TUNNEL_NONE
        ));
        _NDFP_debugf("Tunnel type is none? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2446 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 98:
#line 577 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        switch ((yyvsp[0].us_number)) {
        case _NDFP_TUNNEL_NONE:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::TUNNEL_NONE
            );
            break;
        case _NDFP_TUNNEL_GTP:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::TUNNEL_GTP
            );
            break;
        default:
            _NDFP_result = false;
        }

        (yyval.bool_result) = _NDFP_result;
        _NDFP_debugf("Tunnel type == %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2470 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 99:
#line 596 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        switch ((yyvsp[0].us_number)) {
        case _NDFP_TUNNEL_NONE:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::TUNNEL_NONE
            );
            break;
        case _NDFP_TUNNEL_GTP:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::TUNNEL_GTP
            );
            break;
        default:
            _NDFP_result = false;
        }

        (yyval.bool_result) = _NDFP_result;
        _NDFP_debugf("Tunnel type != %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2494 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 100:
#line 618 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2500 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 101:
#line 619 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2506 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 102:
#line 622 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.detection_guessed.load()));
        _NDFP_debugf("Detection was guessed? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2515 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 103:
#line 626 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = !(_NDFP_flow->flags.detection_guessed.load()));
        _NDFP_debugf(
            "Detection was not guessed? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2526 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 104:
#line 632 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() == true
        ));
        _NDFP_debugf(
            "Detection guessed == true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2539 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 105:
#line 640 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() == false
        ));
        _NDFP_debugf(
            "Detection guessed == false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2552 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 106:
#line 648 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() != true
        ));
        _NDFP_debugf(
            "Detection guessed != true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2565 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 107:
#line 656 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() != false
        ));
        _NDFP_debugf(
            "Detection guessed != false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2578 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 108:
#line 667 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_application != 0
        ));
        _NDFP_debugf("Application detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2589 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 109:
#line 673 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_application == 0
        ));
        _NDFP_debugf(
            "Application not detected? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2602 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 112:
#line 685 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = false);
        if ((yyvsp[0].ul_number) == _NDFP_flow->detected_application)
            _NDFP_result = ((yyval.bool_result) = true);

        _NDFP_debugf(
            "Application ID == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2616 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 113:
#line 694 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = true);
        if ((yyvsp[0].ul_number) == _NDFP_flow->detected_application)
            _NDFP_result = ((yyval.bool_result) = false);

        _NDFP_debugf(
            "Application ID != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2630 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 114:
#line 706 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = false);
        if (_NDFP_flow->detected_application_name != NULL) {

            size_t p;
            string search((yyvsp[0].string));
            string app(_NDFP_flow->detected_application_name);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(
                app.c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ((yyval.bool_result) = true);
            }
            else if ((p = app.find_first_of(".")) != string::npos && strncasecmp(
                app.substr(p + 1).c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ((yyval.bool_result) = true);
            }
        }

        _NDFP_debugf(
            "Application name == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2660 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 115:
#line 731 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = true);
        if (_NDFP_flow->detected_application_name != NULL) {

            size_t p;
            string search((yyvsp[0].string));
            string app(_NDFP_flow->detected_application_name);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(
                app.c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ((yyval.bool_result) = false);
            }
            else if ((p = app.find_first_of(".")) != string::npos && strncasecmp(
                app.substr(p + 1).c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ((yyval.bool_result) = false);
            }
        }

        _NDFP_debugf(
            "Application name != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2690 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 116:
#line 759 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) == _NDFP_flow->category.application
            )
        );

        if (_NDFP_result)
            _NDFP_debugf("App category == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
        else {
            _NDFP_result = (
                (yyval.bool_result) = (
                    nd_categories->LookupTag(
                        ndCAT_TYPE_APP, category) == _NDFP_flow->category.domain
                )
            );
        }
    }
#line 2720 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 117:
#line 784 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) != _NDFP_flow->category.application
            )
        );

        if (_NDFP_result)
            _NDFP_debugf("App category != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
        else {
            _NDFP_result = (
                (yyval.bool_result) = (
                    nd_categories->LookupTag(
                        ndCAT_TYPE_APP, category) != _NDFP_flow->category.domain
                )
            );
        }
    }
#line 2750 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 118:
#line 812 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->risks.size() != 0));
        _NDFP_debugf("Risks detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2759 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 119:
#line 816 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->risks.size() == 0));
        _NDFP_debugf("Risks not detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2768 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 120:
#line 820 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string risk((yyvsp[0].string));

        while ((p = risk.find_first_of("'")) != string::npos)
            risk.erase(p, 1);

        nd_risk_id_t id = nd_risk_lookup(risk);

        _NDFP_result = false;
        for (auto &i : _NDFP_flow->risks) {
            if (i != id) continue;
            _NDFP_result = true;
            break;
        }

        _NDFP_debugf("Risks == %s %s\n", (yyvsp[0].string), risk.c_str(), (_NDFP_result) ? "yes" : "no");
    }
#line 2791 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 121:
#line 838 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string risk((yyvsp[0].string));

        while ((p = risk.find_first_of("'")) != string::npos)
            risk.erase(p, 1);

        nd_risk_id_t id = nd_risk_lookup(risk);

        _NDFP_result = false;
        for (auto &i : _NDFP_flow->risks) {
            if (i != id) continue;
            _NDFP_result = true;
            break;
        }

        _NDFP_result = !_NDFP_result;
        _NDFP_debugf("Risks != %s %s\n", (yyvsp[0].string), risk.c_str(), (_NDFP_result) ? "yes" : "no");
    }
#line 2815 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 122:
#line 860 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score != 0));
        _NDFP_debugf("nDPI risk score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2824 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 123:
#line 864 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score == 0));
        _NDFP_debugf("nDPI risk score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2833 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 124:
#line 868 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score == (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2842 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 125:
#line 872 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score != (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2851 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 126:
#line 876 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score >= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2860 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 127:
#line 880 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score <= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2869 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 128:
#line 884 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score > (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2878 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 129:
#line 888 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score < (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2887 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 130:
#line 895 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client != 0));
        _NDFP_debugf("nDPI risk client score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2896 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 131:
#line 899 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client == 0));
        _NDFP_debugf("nDPI risk client score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2905 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 132:
#line 903 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client == (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2914 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 133:
#line 907 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client != (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2923 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 134:
#line 911 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client >= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2932 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 135:
#line 915 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client <= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2941 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 136:
#line 919 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client > (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2950 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 137:
#line 923 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client < (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2959 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 138:
#line 930 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server != 0));
        _NDFP_debugf("nDPI risk server score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2968 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 139:
#line 934 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server == 0));
        _NDFP_debugf("nDPI risk server score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2977 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 140:
#line 938 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server == (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2986 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 141:
#line 942 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server != (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2995 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 142:
#line 946 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server >= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3004 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 143:
#line 950 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server <= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3013 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 144:
#line 954 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server > (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3022 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 145:
#line 958 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server < (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3031 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 146:
#line 965 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) == _NDFP_flow->category.application
            )
        );

        _NDFP_debugf("App category == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3052 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 147:
#line 981 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) != _NDFP_flow->category.application
            )
        );

        _NDFP_debugf("App category != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3073 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 148:
#line 1000 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) == _NDFP_flow->category.domain
            )
        );

        _NDFP_debugf("Domain category == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3094 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 149:
#line 1016 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) != _NDFP_flow->category.domain
            )
        );

        _NDFP_debugf("Domain category != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3115 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 150:
#line 1035 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol != 0
        ));
        _NDFP_debugf("Protocol detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3126 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 151:
#line 1041 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol == 0
        ));
        _NDFP_debugf("Protocol not detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3137 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 154:
#line 1051 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol == (yyvsp[0].ul_number)
        ));
        _NDFP_debugf("Protocol ID == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3148 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 155:
#line 1057 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol != (yyvsp[0].ul_number)
        ));
        _NDFP_debugf("Protocol ID != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3159 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 156:
#line 1066 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = false);
        if (_NDFP_flow->detected_protocol_name != NULL) {

            size_t p;
            string search((yyvsp[0].string));

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            _NDFP_result = ((yyval.bool_result) = (strncasecmp(
                _NDFP_flow->detected_protocol_name, search.c_str(), _NDFP_MAX_NAMELEN
            ) == 0));
        }

        _NDFP_debugf(
            "Protocol name == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 3183 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 157:
#line 1085 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = true);
        if (_NDFP_flow->detected_protocol_name != NULL) {

            size_t p;
            string search((yyvsp[0].string));

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            _NDFP_result = ((yyval.bool_result) = (strncasecmp(
                _NDFP_flow->detected_protocol_name, search.c_str(), _NDFP_MAX_NAMELEN
            )));
        }
        _NDFP_debugf(
            "Protocol name != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 3206 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 158:
#line 1106 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_PROTO, category) == _NDFP_flow->category.protocol
            )
        );

        _NDFP_debugf("Protocol category == %s? %s\n",
            (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3228 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 159:
#line 1123 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        size_t p;
        string category((yyvsp[0].string));

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            (yyval.bool_result) = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_PROTO, category) != _NDFP_flow->category.protocol
            )
        );

        _NDFP_debugf("Protocol category != %s? %s\n",
            (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3250 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 160:
#line 1143 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->host_server_name[0] != '\0'
        ));
        _NDFP_debugf("Application hostname detected? %s\n",
            (_NDFP_result) ? "yes" : "no");
    }
#line 3262 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 161:
#line 1150 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->host_server_name[0] == '\0'
        ));
        _NDFP_debugf("Application hostname not detected? %s\n",
            (_NDFP_result) ? "yes" : "no");
    }
#line 3274 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 162:
#line 1157 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = false);
        if (_NDFP_flow->host_server_name[0] != '\0') {
            size_t p;
            string search((yyvsp[0].string));

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(search.c_str(),
                _NDFP_flow->host_server_name, _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ((yyval.bool_result) = true);
            }
        }

        _NDFP_debugf("Detected hostname == %s? %s\n",
            (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3297 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 163:
#line 1175 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = true);
        if (_NDFP_flow->host_server_name[0] != '\0') {
            size_t p;
            string search((yyvsp[0].string));

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(search.c_str(),
                _NDFP_flow->host_server_name, _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ((yyval.bool_result) = false);
            }
        }

        _NDFP_debugf("Detected hostname != %s? %s\n",
            (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3320 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 164:
#line 1193 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = false);
#if HAVE_WORKING_REGEX
        if (_NDFP_flow->host_server_name[0] != '\0') {
            size_t p;
            string rx((yyvsp[0].string));

            while ((p = rx.find_first_of("'")) != string::npos)
                rx.erase(p, 1);
            while ((p = rx.find_first_of(":")) != string::npos)
                rx.erase(0, p);

            try {
                // XXX: Unfortunately we're going to compile this everytime...
                regex re(
                    rx,
                    regex_constants::icase |
                    regex_constants::optimize |
                    regex_constants::extended
                );

                cmatch match;
                _NDFP_result = ((yyval.bool_result) = regex_search(
                    _NDFP_flow->host_server_name, match, re
                ));
            } catch (regex_error &e) {
                nd_printf("WARNING: Error compiling regex: %s: %d\n",
                    rx.c_str(), e.code());
            }
        }

        _NDFP_debugf("Detected hostname == %s? %s\n",
            (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_debugf("Detected hostname == %s? Broken regex support.\n", (yyvsp[0].string));
#endif
    }
#line 3362 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 165:
#line 1230 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = true);

        _NDFP_debugf("Detected hostname != %s? %s\n",
            (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3373 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 166:
#line 1239 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark != 0));
        _NDFP_debugf("FWMARK set? %s\n", (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3386 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 167:
#line 1247 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark == 0));
        _NDFP_debugf("FWMARK not set? %s\n", (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3399 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 168:
#line 1255 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark == (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3412 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 169:
#line 1263 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark != (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3425 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 170:
#line 1271 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark >= (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3438 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 171:
#line 1279 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark <= (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3451 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 172:
#line 1287 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark > (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3464 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 173:
#line 1295 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark < (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3477 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 174:
#line 1306 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version != 0));
        _NDFP_debugf("SSL version set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3486 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 175:
#line 1310 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version == 0));
        _NDFP_debugf("SSL version not set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3495 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 176:
#line 1314 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version == (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3504 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 177:
#line 1318 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version != (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3513 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 178:
#line 1322 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version >= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3522 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 179:
#line 1326 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version <= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3531 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 180:
#line 1330 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version > (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3540 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 181:
#line 1334 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version < (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3549 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 182:
#line 1341 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite != 0));
        _NDFP_debugf("SSL cipher suite set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3558 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 183:
#line 1345 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite == 0));
        _NDFP_debugf("SSL cipher suite not set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3567 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 184:
#line 1349 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite == (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3576 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 185:
#line 1353 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite != (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3585 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 186:
#line 1357 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite >= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3594 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 187:
#line 1361 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite <= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3603 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 188:
#line 1365 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite > (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3612 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 189:
#line 1369 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite < (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3621 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 190:
#line 1376 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin != _NDFP_ORIGIN_UNKNOWN));
        _NDFP_debugf("Flow origin known? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3630 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 191:
#line 1380 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin == _NDFP_ORIGIN_UNKNOWN));
        _NDFP_debugf("Flow origin unknown? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3639 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 192:
#line 1384 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin == (yyvsp[0].us_number)));
        _NDFP_debugf("Flow origin == %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3648 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 193:
#line 1388 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin != (yyvsp[0].us_number)));
        _NDFP_debugf("Flow origin != %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3657 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 194:
#line 1395 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 3663 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 195:
#line 1396 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 3669 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 196:
#line 1397 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 3675 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;


#line 3679 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (&yylloc, scanner, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (&yylloc, scanner, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }

  yyerror_range[1] = yylloc;

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, &yylloc, scanner);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  yyerror_range[1] = yylsp[1-yylen];
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, yylsp, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  /* Using YYLLOC is tempting, but would change the location of
     the lookahead.  YYLOC is available though.  */
  YYLLOC_DEFAULT (yyloc, yyerror_range, 2);
  *++yylsp = yyloc;

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, scanner, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, &yylloc, scanner);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, yylsp, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 1399 "nd-flow-criteria.tab.yy" /* yacc.c:1906  */


ndFlowParser::ndFlowParser()
    : flow(NULL), local_mac{}, other_mac{},
    local_ip(NULL), other_ip(NULL), local_port(0), other_port(0),
    origin(0), expr_result(false), scanner(NULL)
{
    yyscan_t scanner;
    yylex_init_extra((void *)this, &scanner);

    if (scanner == NULL)
        throw string("Error creating scanner context");

    this->scanner = (void *)scanner;
}

ndFlowParser::~ndFlowParser()
{
    yylex_destroy((yyscan_t)scanner);
}

bool ndFlowParser::Parse(const ndFlow *flow, const string &expr)
{
    this->flow = flow;
    expr_result = false;

    switch (flow->lower_map) {
    case ndFlow::LOWER_LOCAL:
        local_mac = flow->lower_mac.GetString().c_str();
        other_mac = flow->upper_mac.GetString().c_str();

        local_ip = flow->lower_addr.GetString().c_str();
        other_ip = flow->upper_addr.GetString().c_str();

        local_port = flow->lower_addr.GetPort();
        other_port = flow->upper_addr.GetPort();

        switch (flow->origin) {
        case ndFlow::ORIGIN_LOWER:
            origin = _NDFP_ORIGIN_LOCAL;
            break;
        case ndFlow::ORIGIN_UPPER:
            origin = _NDFP_ORIGIN_OTHER;
            break;
        default:
            origin = _NDFP_ORIGIN_UNKNOWN;
        }
        break;
    case ndFlow::LOWER_OTHER:
        local_mac = flow->upper_mac.GetString().c_str();
        other_mac = flow->lower_mac.GetString().c_str();

        local_ip = flow->upper_addr.GetString().c_str();
        other_ip = flow->lower_addr.GetString().c_str();

        local_port = flow->upper_addr.GetPort();
        other_port = flow->lower_addr.GetPort();

        switch (flow->origin) {
        case ndFlow::ORIGIN_LOWER:
            origin = _NDFP_ORIGIN_OTHER;
            break;
        case ndFlow::ORIGIN_UPPER:
            origin = _NDFP_ORIGIN_LOCAL;
            break;
        default:
            origin = _NDFP_ORIGIN_UNKNOWN;
        }
        break;
    default:
        return false;
    }

    YY_BUFFER_STATE flow_expr_scan_buffer;
    flow_expr_scan_buffer = yy_scan_bytes(
        expr.c_str(), expr.size(), (yyscan_t)scanner
    );

    if (flow_expr_scan_buffer == NULL)
        throw string("Error allocating flow expression scan buffer");

    yy_switch_to_buffer(flow_expr_scan_buffer, (yyscan_t)scanner);

    int rc = 0;

    try {
        rc = yyparse((yyscan_t)scanner);
    } catch (...) {
        yy_delete_buffer(flow_expr_scan_buffer, scanner);
        throw;
    }

    yy_delete_buffer(flow_expr_scan_buffer, scanner);

    return (rc == 0) ? expr_result : false;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
