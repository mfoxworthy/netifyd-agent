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
#include "nd-risks.h"
#include "nd-serializer.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-apps.h"
#include "nd-category.h"
#include "nd-protos.h"
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

#line 158 "nd-flow-criteria.tab.cc" /* yacc.c:316  */



/* Copy the first part of user declarations.  */

#line 164 "nd-flow-criteria.tab.cc" /* yacc.c:339  */

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
#line 100 "nd-flow-criteria.tab.yy" /* yacc.c:355  */

typedef void* yyscan_t;

#line 198 "nd-flow-criteria.tab.cc" /* yacc.c:355  */

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
    FLOW_DETECTION_UPDATED = 271,
    FLOW_CATEGORY = 272,
    FLOW_RISKS = 273,
    FLOW_NDPI_RISK_SCORE = 274,
    FLOW_NDPI_RISK_SCORE_CLIENT = 275,
    FLOW_NDPI_RISK_SCORE_SERVER = 276,
    FLOW_DOMAIN_CATEGORY = 277,
    FLOW_APPLICATION = 278,
    FLOW_APPLICATION_CATEGORY = 279,
    FLOW_PROTOCOL = 280,
    FLOW_PROTOCOL_CATEGORY = 281,
    FLOW_DETECTED_HOSTNAME = 282,
    FLOW_SSL_VERSION = 283,
    FLOW_SSL_CIPHER = 284,
    FLOW_ORIGIN = 285,
    FLOW_CT_MARK = 286,
    FLOW_OTHER_UNKNOWN = 287,
    FLOW_OTHER_UNSUPPORTED = 288,
    FLOW_OTHER_LOCAL = 289,
    FLOW_OTHER_MULTICAST = 290,
    FLOW_OTHER_BROADCAST = 291,
    FLOW_OTHER_REMOTE = 292,
    FLOW_OTHER_ERROR = 293,
    FLOW_ORIGIN_LOCAL = 294,
    FLOW_ORIGIN_OTHER = 295,
    FLOW_ORIGIN_UNKNOWN = 296,
    FLOW_TUNNEL_NONE = 297,
    FLOW_TUNNEL_GTP = 298,
    CMP_EQUAL = 299,
    CMP_NOTEQUAL = 300,
    CMP_GTHANEQUAL = 301,
    CMP_LTHANEQUAL = 302,
    BOOL_AND = 303,
    BOOL_OR = 304,
    VALUE_ADDR_IPMASK = 305,
    VALUE_TRUE = 306,
    VALUE_FALSE = 307,
    VALUE_ADDR_MAC = 308,
    VALUE_ADDR_IPV4 = 309,
    VALUE_ADDR_IPV6 = 310,
    VALUE_NAME = 311,
    VALUE_REGEX = 312,
    VALUE_NUMBER = 313
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
#line 107 "nd-flow-criteria.tab.yy" /* yacc.c:355  */

    char string[_NDFP_MAX_NAMELEN];

    bool bool_number;
    unsigned short us_number;
    unsigned long ul_number;

    bool bool_result;

#line 336 "nd-flow-criteria.tab.cc" /* yacc.c:355  */
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

#line 366 "nd-flow-criteria.tab.cc" /* yacc.c:358  */

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
#define YYLAST   315

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  65
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  40
/* YYNRULES -- Number of rules.  */
#define YYNRULES  203
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  317

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   313

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    62,     2,     2,     2,     2,     2,     2,
      60,    61,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    59,
      64,     2,    63,     2,     2,     2,     2,     2,     2,     2,
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
      55,    56,    57,    58
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   164,   164,   166,   170,   171,   172,   173,   174,   175,
     176,   177,   178,   179,   180,   181,   182,   183,   184,   185,
     186,   187,   188,   189,   190,   191,   192,   193,   194,   195,
     196,   197,   198,   199,   203,   207,   211,   216,   220,   224,
     228,   232,   236,   240,   247,   251,   258,   262,   266,   270,
     274,   278,   285,   289,   293,   297,   301,   305,   309,   313,
     320,   326,   332,   376,   423,   424,   425,   426,   427,   428,
     429,   433,   439,   448,   454,   463,   469,   478,   484,   493,
     494,   498,   502,   506,   510,   514,   518,   522,   526,   533,
     537,   541,   545,   549,   553,   557,   561,   568,   574,   580,
     599,   621,   622,   625,   629,   635,   643,   651,   659,   670,
     674,   680,   688,   696,   704,   715,   721,   729,   730,   733,
     742,   754,   779,   807,   832,   860,   864,   868,   886,   908,
     912,   916,   920,   924,   928,   932,   936,   943,   947,   951,
     955,   959,   963,   967,   971,   978,   982,   986,   990,   994,
     998,  1002,  1006,  1013,  1029,  1048,  1064,  1083,  1089,  1095,
    1096,  1099,  1105,  1114,  1133,  1154,  1171,  1191,  1198,  1205,
    1223,  1241,  1278,  1287,  1295,  1303,  1311,  1319,  1327,  1335,
    1343,  1354,  1358,  1362,  1366,  1370,  1374,  1378,  1382,  1389,
    1393,  1397,  1401,  1405,  1409,  1413,  1417,  1424,  1428,  1432,
    1436,  1443,  1444,  1445
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
  "FLOW_DETECTION_UPDATED", "FLOW_CATEGORY", "FLOW_RISKS",
  "FLOW_NDPI_RISK_SCORE", "FLOW_NDPI_RISK_SCORE_CLIENT",
  "FLOW_NDPI_RISK_SCORE_SERVER", "FLOW_DOMAIN_CATEGORY",
  "FLOW_APPLICATION", "FLOW_APPLICATION_CATEGORY", "FLOW_PROTOCOL",
  "FLOW_PROTOCOL_CATEGORY", "FLOW_DETECTED_HOSTNAME", "FLOW_SSL_VERSION",
  "FLOW_SSL_CIPHER", "FLOW_ORIGIN", "FLOW_CT_MARK", "FLOW_OTHER_UNKNOWN",
  "FLOW_OTHER_UNSUPPORTED", "FLOW_OTHER_LOCAL", "FLOW_OTHER_MULTICAST",
  "FLOW_OTHER_BROADCAST", "FLOW_OTHER_REMOTE", "FLOW_OTHER_ERROR",
  "FLOW_ORIGIN_LOCAL", "FLOW_ORIGIN_OTHER", "FLOW_ORIGIN_UNKNOWN",
  "FLOW_TUNNEL_NONE", "FLOW_TUNNEL_GTP", "CMP_EQUAL", "CMP_NOTEQUAL",
  "CMP_GTHANEQUAL", "CMP_LTHANEQUAL", "BOOL_AND", "BOOL_OR",
  "VALUE_ADDR_IPMASK", "VALUE_TRUE", "VALUE_FALSE", "VALUE_ADDR_MAC",
  "VALUE_ADDR_IPV4", "VALUE_ADDR_IPV6", "VALUE_NAME", "VALUE_REGEX",
  "VALUE_NUMBER", "';'", "'('", "')'", "'!'", "'>'", "'<'", "$accept",
  "exprs", "expr", "expr_ip_proto", "expr_ip_version", "expr_ip_nat",
  "expr_vlan_id", "expr_other_type", "value_other_type", "expr_local_mac",
  "expr_other_mac", "expr_local_ip", "expr_other_ip", "value_addr_ip",
  "expr_local_port", "expr_other_port", "expr_tunnel_type",
  "value_tunnel_type", "expr_detection_guessed", "expr_detection_updated",
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
     305,   306,   307,   308,   309,   310,   311,   312,   313,    59,
      40,    41,    33,    62,    60
};
# endif

#define YYPACT_NINF -50

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-50)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -50,     1,   -50,   -11,    62,   102,    -7,   106,   115,   135,
     140,   144,    85,    89,   148,   159,   161,   163,   165,    94,
      98,   119,   167,   169,   171,   173,   175,   177,   123,   127,
     179,   131,    61,    97,    -1,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -17,    -4,
      40,    43,    47,    50,    56,    79,   -49,   174,    96,   178,
     190,   191,   192,   194,   164,   164,     6,    66,   128,   198,
     176,   176,   176,   176,   195,   196,   197,   199,   200,   201,
     202,   203,   204,   205,   206,   207,   185,   185,   181,   183,
     186,   188,   210,   211,   212,   213,   214,   215,   216,   217,
     218,   219,   220,   221,   222,   223,   224,   225,   226,   227,
     228,   229,   230,   231,   234,   235,     4,    37,   236,   237,
      38,    41,   238,   239,   187,   189,   240,   241,   242,   243,
     244,   245,   246,   247,   248,   249,   250,   251,     5,     5,
     252,   253,   254,   255,   256,   257,    -6,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,    61,    61,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   193,   193
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,    36,     0,    46,    52,    60,     0,     0,
       0,     0,    81,    89,    97,   103,   109,     0,   125,   129,
     137,   145,     0,   115,     0,   157,     0,   167,   181,   189,
     197,   173,     0,     0,     0,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    23,
     117,   118,    18,    19,    20,    21,    22,    24,    25,    26,
     159,   160,    27,    28,    32,    29,    30,    31,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    37,    47,    53,
      61,    82,    90,    98,   104,   110,   126,   130,   138,   146,
     116,   158,   168,   182,   190,   198,   174,     0,     0,     3,
      38,    39,    40,    41,    42,    43,    44,    45,    48,    49,
      50,    51,    54,    55,    56,    57,    58,    59,    64,    65,
      66,    67,    68,    69,    70,    62,    63,    71,    72,    73,
      74,    79,    80,    75,    76,    77,    78,    83,    84,    85,
      86,    87,    88,    91,    92,    93,    94,    95,    96,   101,
     102,    99,   100,   105,   106,   107,   108,   111,   112,   113,
     114,   123,   124,   127,   128,   131,   132,   133,   134,   135,
     136,   139,   140,   141,   142,   143,   144,   147,   148,   149,
     150,   151,   152,   155,   156,   121,   119,   122,   120,   153,
     154,   163,   161,   164,   162,   165,   166,   169,   171,   170,
     172,   183,   184,   185,   186,   187,   188,   191,   192,   193,
     194,   195,   196,   201,   202,   203,   199,   200,   175,   176,
     177,   178,   179,   180,    35,    34,    33
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -50,   -50,   -32,   -50,   -50,   -50,   -50,   -50,   162,   -50,
     -50,   -50,   -50,   -42,   -50,   -50,   -50,   122,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,
     -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   -50,   111
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    34,    35,    36,    37,    38,    39,   215,    40,
      41,    42,    43,   223,    44,    45,    46,   241,    47,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,   306
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint16 yytable[] =
{
     166,     2,   198,   199,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    68,    69,    70,    71,    78,    79,    80,
      81,   190,   187,   188,   303,   304,   305,   187,   188,   224,
     225,   226,    72,    73,   191,   314,    82,    83,   189,   217,
     275,    32,   276,    33,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,   277,   281,   278,   282,   283,   192,   284,
     167,   193,   168,   169,   170,   194,    74,    75,   195,   171,
     172,   173,   174,   175,   196,   176,   177,   178,   179,   218,
     180,    32,   181,    33,   182,   183,   184,   185,   186,    94,
      95,    96,    97,   100,   101,   102,   103,   197,   116,   117,
     118,   119,   122,   123,   124,   125,    76,    77,    98,    99,
      84,    85,   104,   105,   202,   315,   316,   120,   121,    86,
      87,   126,   127,   128,   129,   130,   131,   146,   147,   148,
     149,   152,   153,   154,   155,   160,   161,   162,   163,    88,
      89,   219,   132,   133,    90,    91,   150,   151,    92,    93,
     156,   157,   106,   107,   164,   165,   208,   209,   210,   211,
     212,   213,   214,   108,   109,   110,   111,   112,   113,   114,
     115,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   158,   159,   200,   201,   239,   240,   242,
     221,   222,   243,   244,   245,   246,   203,   247,   248,   249,
     250,   187,   188,   287,   288,   289,   290,   216,   204,   205,
     206,   220,   207,   227,   228,   229,     0,   230,   231,   232,
     233,   234,   235,   236,   237,   238,   251,   252,   253,   254,
     307,     0,   255,   256,   257,   258,   259,   260,   261,   262,
     263,   264,   265,   266,   267,   268,   269,   270,   271,   272,
     273,   274,   279,   280,   285,   286,     0,     0,   291,   292,
     293,   294,   295,   296,   297,   298,   299,   300,   301,   302,
     308,   309,   310,   311,   312,   313
};

static const yytype_int16 yycheck[] =
{
      32,     0,    51,    52,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    44,    45,    46,    47,    44,    45,    46,
      47,    58,    48,    49,    39,    40,    41,    48,    49,    91,
      92,    93,    63,    64,    58,    61,    63,    64,    59,    53,
      56,    60,    58,    62,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    56,    56,    58,    58,    56,    58,    58,
       3,    58,     5,     6,     7,    58,    44,    45,    58,    12,
      13,    14,    15,    16,    58,    18,    19,    20,    21,    53,
      23,    60,    25,    62,    27,    28,    29,    30,    31,    44,
      45,    46,    47,    44,    45,    46,    47,    58,    44,    45,
      46,    47,    44,    45,    46,    47,    44,    45,    63,    64,
      44,    45,    63,    64,    58,   187,   188,    63,    64,    44,
      45,    63,    64,    44,    45,    46,    47,    44,    45,    46,
      47,    44,    45,    46,    47,    44,    45,    46,    47,    44,
      45,    53,    63,    64,    44,    45,    63,    64,    44,    45,
      63,    64,    44,    45,    63,    64,    32,    33,    34,    35,
      36,    37,    38,    44,    45,    44,    45,    44,    45,    44,
      45,    44,    45,    44,    45,    44,    45,    44,    45,    44,
      45,    44,    45,    44,    45,    51,    52,    42,    43,   107,
      54,    55,    51,    52,    51,    52,    58,    51,    52,    51,
      52,    48,    49,    56,    57,    56,    57,    85,    58,    58,
      58,    53,    58,    58,    58,    58,    -1,    58,    58,    58,
      58,    58,    58,    58,    58,    58,    56,    56,    56,    56,
     159,    -1,    58,    58,    58,    58,    58,    58,    58,    58,
      58,    58,    58,    58,    58,    58,    58,    58,    58,    58,
      56,    56,    56,    56,    56,    56,    -1,    -1,    58,    58,
      58,    58,    58,    58,    58,    58,    58,    58,    58,    58,
      58,    58,    58,    58,    58,    58
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    66,     0,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    60,    62,    67,    68,    69,    70,    71,    72,
      74,    75,    76,    77,    79,    80,    81,    83,    84,    85,
      86,    87,    88,    89,    90,    91,    92,    93,    94,    95,
      96,    97,    98,    99,   100,   101,   102,   103,    44,    45,
      46,    47,    63,    64,    44,    45,    44,    45,    44,    45,
      46,    47,    63,    64,    44,    45,    44,    45,    44,    45,
      44,    45,    44,    45,    44,    45,    46,    47,    63,    64,
      44,    45,    46,    47,    63,    64,    44,    45,    44,    45,
      44,    45,    44,    45,    44,    45,    44,    45,    46,    47,
      63,    64,    44,    45,    46,    47,    63,    64,    44,    45,
      46,    47,    63,    64,    44,    45,    44,    45,    44,    45,
      44,    45,    44,    45,    44,    45,    44,    45,    46,    47,
      63,    64,    44,    45,    46,    47,    63,    64,    44,    45,
      44,    45,    46,    47,    63,    64,    67,     3,     5,     6,
       7,    12,    13,    14,    15,    16,    18,    19,    20,    21,
      23,    25,    27,    28,    29,    30,    31,    48,    49,    59,
      58,    58,    58,    58,    58,    58,    58,    58,    51,    52,
      51,    52,    58,    58,    58,    58,    58,    58,    32,    33,
      34,    35,    36,    37,    38,    73,    73,    53,    53,    53,
      53,    54,    55,    78,    78,    78,    78,    58,    58,    58,
      58,    58,    58,    58,    58,    58,    58,    58,    58,    42,
      43,    82,    82,    51,    52,    51,    52,    51,    52,    51,
      52,    56,    56,    56,    56,    58,    58,    58,    58,    58,
      58,    58,    58,    58,    58,    58,    58,    58,    58,    58,
      58,    58,    58,    56,    56,    56,    58,    56,    58,    56,
      56,    56,    58,    56,    58,    56,    56,    56,    57,    56,
      57,    58,    58,    58,    58,    58,    58,    58,    58,    58,
      58,    58,    58,    39,    40,    41,   104,   104,    58,    58,
      58,    58,    58,    58,    61,    67,    67
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    65,    66,    66,    67,    67,    67,    67,    67,    67,
      67,    67,    67,    67,    67,    67,    67,    67,    67,    67,
      67,    67,    67,    67,    67,    67,    67,    67,    67,    67,
      67,    67,    67,    67,    67,    67,    68,    68,    68,    68,
      68,    68,    68,    68,    69,    69,    70,    70,    70,    70,
      70,    70,    71,    71,    71,    71,    71,    71,    71,    71,
      72,    72,    72,    72,    73,    73,    73,    73,    73,    73,
      73,    74,    74,    75,    75,    76,    76,    77,    77,    78,
      78,    79,    79,    79,    79,    79,    79,    79,    79,    80,
      80,    80,    80,    80,    80,    80,    80,    81,    81,    81,
      81,    82,    82,    83,    83,    83,    83,    83,    83,    84,
      84,    84,    84,    84,    84,    85,    85,    85,    85,    86,
      86,    87,    87,    88,    88,    89,    89,    89,    89,    90,
      90,    90,    90,    90,    90,    90,    90,    91,    91,    91,
      91,    91,    91,    91,    91,    92,    92,    92,    92,    92,
      92,    92,    92,    93,    93,    94,    94,    95,    95,    95,
      95,    96,    96,    97,    97,    98,    98,    99,    99,    99,
      99,    99,    99,   100,   100,   100,   100,   100,   100,   100,
     100,   101,   101,   101,   101,   101,   101,   101,   101,   102,
     102,   102,   102,   102,   102,   102,   102,   103,   103,   103,
     103,   104,   104,   104
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     3,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     3,     3,     3,     1,     2,     3,     3,
       3,     3,     3,     3,     3,     3,     1,     2,     3,     3,
       3,     3,     1,     2,     3,     3,     3,     3,     3,     3,
       1,     2,     3,     3,     1,     1,     1,     1,     1,     1,
       1,     3,     3,     3,     3,     3,     3,     3,     3,     1,
       1,     1,     2,     3,     3,     3,     3,     3,     3,     1,
       2,     3,     3,     3,     3,     3,     3,     1,     2,     3,
       3,     1,     1,     1,     2,     3,     3,     3,     3,     1,
       2,     3,     3,     3,     3,     1,     2,     1,     1,     3,
       3,     3,     3,     3,     3,     1,     2,     3,     3,     1,
       2,     3,     3,     3,     3,     3,     3,     1,     2,     3,
       3,     3,     3,     3,     3,     1,     2,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     1,     2,     1,
       1,     3,     3,     3,     3,     3,     3,     1,     2,     3,
       3,     3,     3,     1,     2,     3,     3,     3,     3,     3,
       3,     1,     2,     3,     3,     3,     3,     3,     3,     1,
       2,     3,     3,     3,     3,     3,     3,     1,     2,     3,
       3,     1,     1,     1
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
        case 33:
#line 199 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = ((yyvsp[-2].bool_result) || (yyvsp[0].bool_result)));
        _NDFP_debugf("OR (%d || %d == %d)\n", (yyvsp[-2].bool_result), (yyvsp[0].bool_result), (yyval.bool_result));
    }
#line 1798 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 34:
#line 203 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = ((yyvsp[-2].bool_result) && (yyvsp[0].bool_result)));
        _NDFP_debugf("AND (%d && %d == %d)\n", (yyvsp[-2].bool_result), (yyvsp[0].bool_result), (yyval.bool_result));
    }
#line 1807 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 35:
#line 207 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { _NDFP_result = ((yyval.bool_result) = (yyvsp[-1].bool_result)); }
#line 1813 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 36:
#line 211 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol != 0));
        _NDFP_debugf(
            "IP Protocol is non-zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1823 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 37:
#line 216 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol == 0));
        _NDFP_debugf("IP Protocol is zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1832 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 38:
#line 220 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol == (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1841 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 39:
#line 224 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol != (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1850 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 40:
#line 228 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol >= (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1859 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 41:
#line 232 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol <= (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1868 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 42:
#line 236 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol > (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1877 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 43:
#line 240 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_protocol < (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Protocol > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1886 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 44:
#line 247 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_version == (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Version == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1895 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 45:
#line 251 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ip_version != (yyvsp[0].ul_number)));
        _NDFP_debugf("IP Version != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1904 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 46:
#line 258 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == true));
        _NDFP_debugf("IP NAT is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1913 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 47:
#line 262 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == false));
        _NDFP_debugf("IP NAT is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1922 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 48:
#line 266 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == true));
        _NDFP_debugf("IP NAT == true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1931 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 49:
#line 270 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() == false));
        _NDFP_debugf("IP NAT == false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1940 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 50:
#line 274 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() != true));
        _NDFP_debugf("IP NAT != true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1949 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 51:
#line 278 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.ip_nat.load() != false));
        _NDFP_debugf("IP NAT != false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1958 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 52:
#line 285 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id != 0));
        _NDFP_debugf("VLAN ID is non-zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1967 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 53:
#line 289 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id == 0));
        _NDFP_debugf("VLAN ID is zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 1976 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 54:
#line 293 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id == (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1985 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 55:
#line 297 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id != (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 1994 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 56:
#line 301 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id >= (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2003 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 57:
#line 305 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id <= (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2012 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 58:
#line 309 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id > (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2021 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 59:
#line 313 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->vlan_id < (yyvsp[0].ul_number)));
        _NDFP_debugf("VLAN ID < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2030 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 60:
#line 320 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->other_type != ndFlow::OTHER_UNKNOWN
        ));
        _NDFP_debugf("Other type known? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2041 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 61:
#line 326 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->other_type == ndFlow::OTHER_UNKNOWN
        ));
        _NDFP_debugf("Other type unknown? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2052 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 62:
#line 332 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2101 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 63:
#line 376 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2150 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 64:
#line 423 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2156 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 65:
#line 424 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2162 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 66:
#line 425 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2168 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 67:
#line 426 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2174 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 68:
#line 427 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2180 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 69:
#line 428 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2186 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 70:
#line 429 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2192 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 71:
#line 433 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_mac, (yyvsp[0].string), ND_STR_ETHALEN) == 0
        ));
        _NDFP_debugf("Local MAC == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2203 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 72:
#line 439 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_mac, (yyvsp[0].string), ND_STR_ETHALEN) != 0
        ));
        _NDFP_debugf("Local MAC != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2214 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 73:
#line 448 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_mac, (yyvsp[0].string), ND_STR_ETHALEN) == 0
        ));
        _NDFP_debugf("Other MAC == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2225 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 74:
#line 454 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_mac, (yyvsp[0].string), ND_STR_ETHALEN) != 0
        ));
        _NDFP_debugf("Other MAC != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2236 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 75:
#line 463 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) == 0
        ));
        _NDFP_debugf("Local IP == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2247 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 76:
#line 469 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_local_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) != 0
        ));
        _NDFP_debugf("Local IP != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2258 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 77:
#line 478 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) == 0
        ));
        _NDFP_debugf("Other IP == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2269 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 78:
#line 484 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            strncasecmp(_NDFP_other_ip, (yyvsp[0].string), INET6_ADDRSTRLEN) != 0
        ));
        _NDFP_debugf("Other IP != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2280 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 79:
#line 493 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { strncpy((yyval.string), (yyvsp[0].string), _NDFP_MAX_NAMELEN); }
#line 2286 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 80:
#line 494 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { strncpy((yyval.string), (yyvsp[0].string), _NDFP_MAX_NAMELEN); }
#line 2292 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 81:
#line 498 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port != 0));
        _NDFP_debugf("Local port is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2301 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 82:
#line 502 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port == 0));
        _NDFP_debugf("Local port is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2310 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 83:
#line 506 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port == (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2319 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 84:
#line 510 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port != (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2328 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 85:
#line 514 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port >= (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2337 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 86:
#line 518 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port <= (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2346 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 87:
#line 522 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port > (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2355 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 88:
#line 526 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_local_port < (yyvsp[0].ul_number)));
        _NDFP_debugf("Local port > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2364 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 89:
#line 533 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port != 0));
        _NDFP_debugf("Other port is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2373 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 90:
#line 537 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port == 0));
        _NDFP_debugf("Other port is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2382 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 91:
#line 541 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port == (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2391 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 92:
#line 545 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port != (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2400 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 93:
#line 549 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port >= (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2409 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 94:
#line 553 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port <= (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2418 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 95:
#line 557 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port > (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2427 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 96:
#line 561 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_other_port < (yyvsp[0].ul_number)));
        _NDFP_debugf("Other port > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2436 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 97:
#line 568 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->tunnel_type != ndFlow::TUNNEL_NONE
        ));
        _NDFP_debugf("Tunnel type set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2447 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 98:
#line 574 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->tunnel_type == ndFlow::TUNNEL_NONE
        ));
        _NDFP_debugf("Tunnel type is none? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2458 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 99:
#line 580 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2482 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 100:
#line 599 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2506 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 101:
#line 621 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2512 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 102:
#line 622 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 2518 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 103:
#line 625 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.detection_guessed.load()));
        _NDFP_debugf("Detection was guessed? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2527 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 104:
#line 629 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = !(_NDFP_flow->flags.detection_guessed.load()));
        _NDFP_debugf(
            "Detection was not guessed? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2538 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 105:
#line 635 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() == true
        ));
        _NDFP_debugf(
            "Detection guessed == true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2551 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 106:
#line 643 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() == false
        ));
        _NDFP_debugf(
            "Detection guessed == false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2564 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 107:
#line 651 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() != true
        ));
        _NDFP_debugf(
            "Detection guessed != true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2577 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 108:
#line 659 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_guessed.load() != false
        ));
        _NDFP_debugf(
            "Detection guessed != false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2590 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 109:
#line 670 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->flags.detection_updated.load()));
        _NDFP_debugf("Detection was updated? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2599 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 110:
#line 674 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = !(_NDFP_flow->flags.detection_updated.load()));
        _NDFP_debugf(
            "Detection was not updated? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2610 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 111:
#line 680 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_updated.load() == true
        ));
        _NDFP_debugf(
            "Detection updated == true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2623 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 112:
#line 688 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_updated.load() == false
        ));
        _NDFP_debugf(
            "Detection updated == false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2636 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 113:
#line 696 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_updated.load() != true
        ));
        _NDFP_debugf(
            "Detection updated != true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2649 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 114:
#line 704 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->flags.detection_updated.load() != false
        ));
        _NDFP_debugf(
            "Detection updated != false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2662 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 115:
#line 715 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_application != 0
        ));
        _NDFP_debugf("Application detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2673 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 116:
#line 721 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_application == 0
        ));
        _NDFP_debugf(
            "Application not detected? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2686 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 119:
#line 733 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = false);
        if ((yyvsp[0].ul_number) == _NDFP_flow->detected_application)
            _NDFP_result = ((yyval.bool_result) = true);

        _NDFP_debugf(
            "Application ID == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2700 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 120:
#line 742 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = true);
        if ((yyvsp[0].ul_number) == _NDFP_flow->detected_application)
            _NDFP_result = ((yyval.bool_result) = false);

        _NDFP_debugf(
            "Application ID != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no"
        );
    }
#line 2714 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 121:
#line 754 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2744 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 122:
#line 779 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2774 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 123:
#line 807 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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

        if (! _NDFP_result) {
            _NDFP_result = (
                (yyval.bool_result) = (
                    nd_categories->LookupTag(
                        ndCAT_TYPE_APP, category) == _NDFP_flow->category.domain
                )
            );
        }

        _NDFP_debugf("App/domain category == %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2804 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 124:
#line 832 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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

        if (! _NDFP_result) {
            _NDFP_result = (
                (yyval.bool_result) = (
                    nd_categories->LookupTag(
                        ndCAT_TYPE_APP, category) != _NDFP_flow->category.domain
                )
            );
        }

        _NDFP_debugf("App/domain category != %s? %s\n", (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 2834 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 125:
#line 860 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->risks.size() != 0));
        _NDFP_debugf("Risks detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2843 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 126:
#line 864 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->risks.size() == 0));
        _NDFP_debugf("Risks not detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2852 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 127:
#line 868 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2875 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 128:
#line 886 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 2899 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 129:
#line 908 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score != 0));
        _NDFP_debugf("nDPI risk score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2908 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 130:
#line 912 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score == 0));
        _NDFP_debugf("nDPI risk score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2917 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 131:
#line 916 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score == (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2926 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 132:
#line 920 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score != (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2935 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 133:
#line 924 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score >= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2944 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 134:
#line 928 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score <= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2953 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 135:
#line 932 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score > (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2962 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 136:
#line 936 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score < (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2971 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 137:
#line 943 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client != 0));
        _NDFP_debugf("nDPI risk client score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2980 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 138:
#line 947 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client == 0));
        _NDFP_debugf("nDPI risk client score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 2989 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 139:
#line 951 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client == (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 2998 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 140:
#line 955 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client != (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3007 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 141:
#line 959 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client >= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3016 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 142:
#line 963 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client <= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3025 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 143:
#line 967 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client > (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3034 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 144:
#line 971 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_client < (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk client score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3043 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 145:
#line 978 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server != 0));
        _NDFP_debugf("nDPI risk server score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3052 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 146:
#line 982 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server == 0));
        _NDFP_debugf("nDPI risk server score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3061 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 147:
#line 986 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server == (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score == %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3070 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 148:
#line 990 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server != (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score != %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3079 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 149:
#line 994 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server >= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score >= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3088 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 150:
#line 998 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server <= (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score <= %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3097 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 151:
#line 1002 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server > (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3106 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 152:
#line 1006 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ndpi_risk_score_server < (yyvsp[0].ul_number)));
        _NDFP_debugf("nDPI risk server score > %lu %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3115 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 153:
#line 1013 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3136 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 154:
#line 1029 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3157 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 155:
#line 1048 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3178 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 156:
#line 1064 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3199 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 157:
#line 1083 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol != 0
        ));
        _NDFP_debugf("Protocol detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3210 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 158:
#line 1089 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol == 0
        ));
        _NDFP_debugf("Protocol not detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3221 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 161:
#line 1099 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol == (yyvsp[0].ul_number)
        ));
        _NDFP_debugf("Protocol ID == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3232 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 162:
#line 1105 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->detected_protocol != (yyvsp[0].ul_number)
        ));
        _NDFP_debugf("Protocol ID != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3243 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 163:
#line 1114 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3267 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 164:
#line 1133 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3290 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 165:
#line 1154 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3312 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 166:
#line 1171 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3334 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 167:
#line 1191 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->host_server_name[0] != '\0'
        ));
        _NDFP_debugf("Application hostname detected? %s\n",
            (_NDFP_result) ? "yes" : "no");
    }
#line 3346 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 168:
#line 1198 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (
            _NDFP_flow->host_server_name[0] == '\0'
        ));
        _NDFP_debugf("Application hostname not detected? %s\n",
            (_NDFP_result) ? "yes" : "no");
    }
#line 3358 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 169:
#line 1205 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3381 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 170:
#line 1223 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3404 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 171:
#line 1241 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
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
#line 3446 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 172:
#line 1278 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = true);

        _NDFP_debugf("Detected hostname != %s? %s\n",
            (yyvsp[0].string), (_NDFP_result) ? "yes" : "no");
    }
#line 3457 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 173:
#line 1287 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark != 0));
        _NDFP_debugf("FWMARK set? %s\n", (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3470 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 174:
#line 1295 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark == 0));
        _NDFP_debugf("FWMARK not set? %s\n", (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3483 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 175:
#line 1303 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark == (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3496 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 176:
#line 1311 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark != (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3509 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 177:
#line 1319 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark >= (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3522 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 178:
#line 1327 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark <= (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3535 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 179:
#line 1335 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark > (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3548 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 180:
#line 1343 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ct_mark < (yyvsp[0].ul_number)));
        _NDFP_debugf("FWMARK < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ((yyval.bool_result) = (false));
#endif
    }
#line 3561 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 181:
#line 1354 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version != 0));
        _NDFP_debugf("SSL version set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3570 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 182:
#line 1358 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version == 0));
        _NDFP_debugf("SSL version not set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3579 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 183:
#line 1362 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version == (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3588 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 184:
#line 1366 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version != (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3597 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 185:
#line 1370 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version >= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3606 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 186:
#line 1374 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version <= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3615 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 187:
#line 1378 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version > (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3624 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 188:
#line 1382 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.version < (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL version < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3633 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 189:
#line 1389 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite != 0));
        _NDFP_debugf("SSL cipher suite set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3642 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 190:
#line 1393 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite == 0));
        _NDFP_debugf("SSL cipher suite not set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3651 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 191:
#line 1397 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite == (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite == %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3660 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 192:
#line 1401 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite != (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite != %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3669 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 193:
#line 1405 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite >= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite >= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3678 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 194:
#line 1409 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite <= (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite <= %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3687 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 195:
#line 1413 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite > (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite > %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3696 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 196:
#line 1417 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_flow->ssl.cipher_suite < (yyvsp[0].ul_number)));
        _NDFP_debugf("SSL cipher suite < %lu? %s\n", (yyvsp[0].ul_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3705 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 197:
#line 1424 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin != _NDFP_ORIGIN_UNKNOWN));
        _NDFP_debugf("Flow origin known? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3714 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 198:
#line 1428 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin == _NDFP_ORIGIN_UNKNOWN));
        _NDFP_debugf("Flow origin unknown? %s\n", (_NDFP_result) ? "yes" : "no");
    }
#line 3723 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 199:
#line 1432 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin == (yyvsp[0].us_number)));
        _NDFP_debugf("Flow origin == %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3732 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 200:
#line 1436 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    {
        _NDFP_result = ((yyval.bool_result) = (_NDFP_origin != (yyvsp[0].us_number)));
        _NDFP_debugf("Flow origin != %hu? %s\n", (yyvsp[0].us_number), (_NDFP_result) ? "yes" : "no");
    }
#line 3741 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 201:
#line 1443 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 3747 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 202:
#line 1444 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 3753 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;

  case 203:
#line 1445 "nd-flow-criteria.tab.yy" /* yacc.c:1646  */
    { (yyval.us_number) = (yyvsp[0].us_number); }
#line 3759 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
    break;


#line 3763 "nd-flow-criteria.tab.cc" /* yacc.c:1646  */
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
#line 1447 "nd-flow-criteria.tab.yy" /* yacc.c:1906  */


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
        //nd_dprintf("Bad lower map: %u\n", flow->lower_map);
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
