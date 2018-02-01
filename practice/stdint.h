 /*===---- stdint.h - Standard header for sized integer types --------------===*\
    2  *
    3  * Copyright (c) 2009 Chris Lattner
    4  *
    5  * Permission is hereby granted, free of charge, to any person obtaining a copy
    6  * of this software and associated documentation files (the "Software"), to deal
    7  * in the Software without restriction, including without limitation the rights
    8  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    9  * copies of the Software, and to permit persons to whom the Software is
   10  * furnished to do so, subject to the following conditions:
   11  *
   12  * The above copyright notice and this permission notice shall be included in
   13  * all copies or substantial portions of the Software.
   14  *
   15  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   16  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   17  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   18  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   19  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   20  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   21  * THE SOFTWARE.
   22  *
   23 \*===----------------------------------------------------------------------===*/
   24 
   25 #ifndef __CLANG_STDINT_H
   26 #define __CLANG_STDINT_H
   27 
   28 /* If we're hosted, fall back to the system's stdint.h, which might have
   29  * additional definitions.
   30  */
   31 #if __STDC_HOSTED__ && __has_include_next(<stdint.h>)
   32 
   33 // C99 7.18.3 Limits of other integer types
   34 //
   35 //  Footnote 219, 220: C++ implementations should define these macros only when
   36 //  __STDC_LIMIT_MACROS is defined before <stdint.h> is included.
   37 //
   38 //  Footnote 222: C++ implementations should define these macros only when
   39 //  __STDC_CONSTANT_MACROS is defined before <stdint.h> is included.
   40 //
   41 // C++11 [cstdint.syn]p2:
   42 //
   43 //  The macros defined by <cstdint> are provided unconditionally. In particular,
   44 //  the symbols __STDC_LIMIT_MACROS and __STDC_CONSTANT_MACROS (mentioned in
   45 //  footnotes 219, 220, and 222 in the C standard) play no role in C++.
   46 //
   47 // C11 removed the problematic footnotes.
   48 //
   49 // Work around this inconsistency by always defining those macros in C++ mode,
   50 // so that a C library implementation which follows the C99 standard can be
   51 // used in C++.
   52 # ifdef __cplusplus
   53 #  if !defined(__STDC_LIMIT_MACROS)
   54 #   define __STDC_LIMIT_MACROS
   55 #   define __STDC_LIMIT_MACROS_DEFINED_BY_CLANG
   56 #  endif
   57 #  if !defined(__STDC_CONSTANT_MACROS)
   58 #   define __STDC_CONSTANT_MACROS
   59 #   define __STDC_CONSTANT_MACROS_DEFINED_BY_CLANG
   60 #  endif
   61 # endif
   62 
   63 # include_next <stdint.h>
   64 
   65 # ifdef __STDC_LIMIT_MACROS_DEFINED_BY_CLANG
   66 #  undef __STDC_LIMIT_MACROS
   67 #  undef __STDC_LIMIT_MACROS_DEFINED_BY_CLANG
   68 # endif
   69 # ifdef __STDC_CONSTANT_MACROS_DEFINED_BY_CLANG
   70 #  undef __STDC_CONSTANT_MACROS
   71 #  undef __STDC_CONSTANT_MACROS_DEFINED_BY_CLANG
   72 # endif
   73 
   74 #else
   75 
   76 /* C99 7.18.1.1 Exact-width integer types.
   77  * C99 7.18.1.2 Minimum-width integer types.
   78  * C99 7.18.1.3 Fastest minimum-width integer types.
   79  *
   80  * The standard requires that exact-width type be defined for 8-, 16-, 32-, and
   81  * 64-bit types if they are implemented. Other exact width types are optional.
   82  * This implementation defines an exact-width types for every integer width
   83  * that is represented in the standard integer types.
   84  *
   85  * The standard also requires minimum-width types be defined for 8-, 16-, 32-,
   86  * and 64-bit widths regardless of whether there are corresponding exact-width
   87  * types.
   88  *
   89  * To accommodate targets that are missing types that are exactly 8, 16, 32, or
   90  * 64 bits wide, this implementation takes an approach of cascading
   91  * redefintions, redefining __int_leastN_t to successively smaller exact-width
   92  * types. It is therefore important that the types are defined in order of
   93  * descending widths.
   94  *
   95  * We currently assume that the minimum-width types and the fastest
   96  * minimum-width types are the same. This is allowed by the standard, but is
   97  * suboptimal.
   98  *
   99  * In violation of the standard, some targets do not implement a type that is
  100  * wide enough to represent all of the required widths (8-, 16-, 32-, 64-bit).
  101  * To accommodate these targets, a required minimum-width type is only
  102  * defined if there exists an exact-width type of equal or greater width.
  103  */
  104 
  105 #ifdef __INT64_TYPE__
  106 # ifndef __int8_t_defined /* glibc sys/types.h also defines int64_t*/
  107 typedef __INT64_TYPE__ int64_t;
  108 # endif /* __int8_t_defined */
  109 typedef __UINT64_TYPE__ uint64_t;
  110 # define __int_least64_t int64_t
  111 # define __uint_least64_t uint64_t
  112 # define __int_least32_t int64_t
  113 # define __uint_least32_t uint64_t
  114 # define __int_least16_t int64_t
  115 # define __uint_least16_t uint64_t
  116 # define __int_least8_t int64_t
  117 # define __uint_least8_t uint64_t
  118 #endif /* __INT64_TYPE__ */
  119 
  120 #ifdef __int_least64_t
  121 typedef __int_least64_t int_least64_t;
  122 typedef __uint_least64_t uint_least64_t;
  123 typedef __int_least64_t int_fast64_t;
  124 typedef __uint_least64_t uint_fast64_t;
  125 #endif /* __int_least64_t */
  126 
  127 #ifdef __INT56_TYPE__
  128 typedef __INT56_TYPE__ int56_t;
  129 typedef __UINT56_TYPE__ uint56_t;
  130 typedef int56_t int_least56_t;
  131 typedef uint56_t uint_least56_t;
  132 typedef int56_t int_fast56_t;
  133 typedef uint56_t uint_fast56_t;
  134 # define __int_least32_t int56_t
  135 # define __uint_least32_t uint56_t
  136 # define __int_least16_t int56_t
  137 # define __uint_least16_t uint56_t
  138 # define __int_least8_t int56_t
  139 # define __uint_least8_t uint56_t
  140 #endif /* __INT56_TYPE__ */
  141 
  142 
  143 #ifdef __INT48_TYPE__
  144 typedef __INT48_TYPE__ int48_t;
  145 typedef __UINT48_TYPE__ uint48_t;
  146 typedef int48_t int_least48_t;
  147 typedef uint48_t uint_least48_t;
  148 typedef int48_t int_fast48_t;
  149 typedef uint48_t uint_fast48_t;
  150 # define __int_least32_t int48_t
  151 # define __uint_least32_t uint48_t
  152 # define __int_least16_t int48_t
  153 # define __uint_least16_t uint48_t
  154 # define __int_least8_t int48_t
  155 # define __uint_least8_t uint48_t
  156 #endif /* __INT48_TYPE__ */
  157 
  158 
  159 #ifdef __INT40_TYPE__
  160 typedef __INT40_TYPE__ int40_t;
  161 typedef __UINT40_TYPE__ uint40_t;
  162 typedef int40_t int_least40_t;
  163 typedef uint40_t uint_least40_t;
  164 typedef int40_t int_fast40_t;
  165 typedef uint40_t uint_fast40_t;
  166 # define __int_least32_t int40_t
  167 # define __uint_least32_t uint40_t
  168 # define __int_least16_t int40_t
  169 # define __uint_least16_t uint40_t
  170 # define __int_least8_t int40_t
  171 # define __uint_least8_t uint40_t
  172 #endif /* __INT40_TYPE__ */
  173 
  174 
  175 #ifdef __INT32_TYPE__
  176 
  177 # ifndef __int8_t_defined /* glibc sys/types.h also defines int32_t*/
  178 typedef __INT32_TYPE__ int32_t;
  179 # endif /* __int8_t_defined */
  180 
  181 # ifndef __uint32_t_defined  /* more glibc compatibility */
  182 # define __uint32_t_defined
  183 typedef __UINT32_TYPE__ uint32_t;
  184 # endif /* __uint32_t_defined */
  185 
  186 # define __int_least32_t int32_t
  187 # define __uint_least32_t uint32_t
  188 # define __int_least16_t int32_t
  189 # define __uint_least16_t uint32_t
  190 # define __int_least8_t int32_t
  191 # define __uint_least8_t uint32_t
  192 #endif /* __INT32_TYPE__ */
  193 
  194 #ifdef __int_least32_t
  195 typedef __int_least32_t int_least32_t;
  196 typedef __uint_least32_t uint_least32_t;
  197 typedef __int_least32_t int_fast32_t;
  198 typedef __uint_least32_t uint_fast32_t;
  199 #endif /* __int_least32_t */
  200 
  201 #ifdef __INT24_TYPE__
  202 typedef __INT24_TYPE__ int24_t;
  203 typedef __UINT24_TYPE__ uint24_t;
  204 typedef int24_t int_least24_t;
  205 typedef uint24_t uint_least24_t;
  206 typedef int24_t int_fast24_t;
  207 typedef uint24_t uint_fast24_t;
  208 # define __int_least16_t int24_t
  209 # define __uint_least16_t uint24_t
  210 # define __int_least8_t int24_t
  211 # define __uint_least8_t uint24_t
  212 #endif /* __INT24_TYPE__ */
  213 
  214 #ifdef __INT16_TYPE__
  215 #ifndef __int8_t_defined /* glibc sys/types.h also defines int16_t*/
  216 typedef __INT16_TYPE__ int16_t;
  217 #endif /* __int8_t_defined */
  218 typedef __UINT16_TYPE__ uint16_t;
  219 # define __int_least16_t int16_t
  220 # define __uint_least16_t uint16_t
  221 # define __int_least8_t int16_t
  222 # define __uint_least8_t uint16_t
  223 #endif /* __INT16_TYPE__ */
  224 
  225 #ifdef __int_least16_t
  226 typedef __int_least16_t int_least16_t;
  227 typedef __uint_least16_t uint_least16_t;
  228 typedef __int_least16_t int_fast16_t;
  229 typedef __uint_least16_t uint_fast16_t;
  230 #endif /* __int_least16_t */
  231 
  232 
  233 #ifdef __INT8_TYPE__
  234 #ifndef __int8_t_defined  /* glibc sys/types.h also defines int8_t*/
  235 typedef __INT8_TYPE__ int8_t;
  236 #endif /* __int8_t_defined */
  237 typedef __UINT8_TYPE__ uint8_t;
  238 # define __int_least8_t int8_t
  239 # define __uint_least8_t uint8_t
  240 #endif /* __INT8_TYPE__ */
  241 
  242 #ifdef __int_least8_t
  243 typedef __int_least8_t int_least8_t;
  244 typedef __uint_least8_t uint_least8_t;
  245 typedef __int_least8_t int_fast8_t;
  246 typedef __uint_least8_t uint_fast8_t;
  247 #endif /* __int_least8_t */
  248 
  249 /* prevent glibc sys/types.h from defining conflicting types */
  250 #ifndef __int8_t_defined
  251 # define __int8_t_defined
  252 #endif /* __int8_t_defined */
  253 
  254 /* C99 7.18.1.4 Integer types capable of holding object pointers.
  255  */
  256 #define __stdint_join3(a,b,c) a ## b ## c
  257 
  258 #ifndef _INTPTR_T
  259 #ifndef __intptr_t_defined
  260 typedef __INTPTR_TYPE__ intptr_t;
  261 #define __intptr_t_defined
  262 #define _INTPTR_T
  263 #endif
  264 #endif
  265 
  266 #ifndef _UINTPTR_T
  267 typedef __UINTPTR_TYPE__ uintptr_t;
  268 #define _UINTPTR_T
  269 #endif
  270 
  271 /* C99 7.18.1.5 Greatest-width integer types.
  272  */
  273 typedef __INTMAX_TYPE__  intmax_t;
  274 typedef __UINTMAX_TYPE__ uintmax_t;
  275 
  276 /* C99 7.18.4 Macros for minimum-width integer constants.
  277  *
  278  * The standard requires that integer constant macros be defined for all the
  279  * minimum-width types defined above. As 8-, 16-, 32-, and 64-bit minimum-width
  280  * types are required, the corresponding integer constant macros are defined
  281  * here. This implementation also defines minimum-width types for every other
  282  * integer width that the target implements, so corresponding macros are
  283  * defined below, too.
  284  *
  285  * These macros are defined using the same successive-shrinking approach as
  286  * the type definitions above. It is likewise important that macros are defined
  287  * in order of decending width.
  288  *
  289  * Note that C++ should not check __STDC_CONSTANT_MACROS here, contrary to the
  290  * claims of the C standard (see C++ 18.3.1p2, [cstdint.syn]).
  291  */
  292 
  293 #define __int_c_join(a, b) a ## b
  294 #define __int_c(v, suffix) __int_c_join(v, suffix)
  295 #define __uint_c(v, suffix) __int_c_join(v##U, suffix)
  296 
  297 
  298 #ifdef __INT64_TYPE__
  299 # ifdef __INT64_C_SUFFIX__
  300 #  define __int64_c_suffix __INT64_C_SUFFIX__
  301 #  define __int32_c_suffix __INT64_C_SUFFIX__
  302 #  define __int16_c_suffix __INT64_C_SUFFIX__
  303 #  define  __int8_c_suffix __INT64_C_SUFFIX__
  304 # else
  305 #  undef __int64_c_suffix
  306 #  undef __int32_c_suffix
  307 #  undef __int16_c_suffix
  308 #  undef  __int8_c_suffix
  309 # endif /* __INT64_C_SUFFIX__ */
  310 #endif /* __INT64_TYPE__ */
  311 
  312 #ifdef __int_least64_t
  313 # ifdef __int64_c_suffix
  314 #  define INT64_C(v) __int_c(v, __int64_c_suffix)
  315 #  define UINT64_C(v) __uint_c(v, __int64_c_suffix)
  316 # else
  317 #  define INT64_C(v) v
  318 #  define UINT64_C(v) v ## U
  319 # endif /* __int64_c_suffix */
  320 #endif /* __int_least64_t */
  321 
  322 
  323 #ifdef __INT56_TYPE__
  324 # ifdef __INT56_C_SUFFIX__
  325 #  define INT56_C(v) __int_c(v, __INT56_C_SUFFIX__)
  326 #  define UINT56_C(v) __uint_c(v, __INT56_C_SUFFIX__)
  327 #  define __int32_c_suffix __INT56_C_SUFFIX__
  328 #  define __int16_c_suffix __INT56_C_SUFFIX__
  329 #  define __int8_c_suffix  __INT56_C_SUFFIX__
  330 # else
  331 #  define INT56_C(v) v
  332 #  define UINT56_C(v) v ## U
  333 #  undef __int32_c_suffix
  334 #  undef __int16_c_suffix
  335 #  undef  __int8_c_suffix
  336 # endif /* __INT56_C_SUFFIX__ */
  337 #endif /* __INT56_TYPE__ */
  338 
  339 
  340 #ifdef __INT48_TYPE__
  341 # ifdef __INT48_C_SUFFIX__
  342 #  define INT48_C(v) __int_c(v, __INT48_C_SUFFIX__)
  343 #  define UINT48_C(v) __uint_c(v, __INT48_C_SUFFIX__)
  344 #  define __int32_c_suffix __INT48_C_SUFFIX__
  345 #  define __int16_c_suffix __INT48_C_SUFFIX__
  346 #  define __int8_c_suffix  __INT48_C_SUFFIX__
  347 # else
  348 #  define INT48_C(v) v
  349 #  define UINT48_C(v) v ## U
  350 #  undef __int32_c_suffix
  351 #  undef __int16_c_suffix
  352 #  undef  __int8_c_suffix
  353 # endif /* __INT48_C_SUFFIX__ */
  354 #endif /* __INT48_TYPE__ */
  355 
  356 
  357 #ifdef __INT40_TYPE__
  358 # ifdef __INT40_C_SUFFIX__
  359 #  define INT40_C(v) __int_c(v, __INT40_C_SUFFIX__)
  360 #  define UINT40_C(v) __uint_c(v, __INT40_C_SUFFIX__)
  361 #  define __int32_c_suffix __INT40_C_SUFFIX__
  362 #  define __int16_c_suffix __INT40_C_SUFFIX__
  363 #  define __int8_c_suffix  __INT40_C_SUFFIX__
  364 # else
  365 #  define INT40_C(v) v
  366 #  define UINT40_C(v) v ## U
  367 #  undef __int32_c_suffix
  368 #  undef __int16_c_suffix
  369 #  undef  __int8_c_suffix
  370 # endif /* __INT40_C_SUFFIX__ */
  371 #endif /* __INT40_TYPE__ */
  372 
  373 
  374 #ifdef __INT32_TYPE__
  375 # ifdef __INT32_C_SUFFIX__
  376 #  define __int32_c_suffix __INT32_C_SUFFIX__
  377 #  define __int16_c_suffix __INT32_C_SUFFIX__
  378 #  define __int8_c_suffix  __INT32_C_SUFFIX__
  379 #else
  380 #  undef __int32_c_suffix
  381 #  undef __int16_c_suffix
  382 #  undef  __int8_c_suffix
  383 # endif /* __INT32_C_SUFFIX__ */
  384 #endif /* __INT32_TYPE__ */
  385 
  386 #ifdef __int_least32_t
  387 # ifdef __int32_c_suffix
  388 #  define INT32_C(v) __int_c(v, __int32_c_suffix)
  389 #  define UINT32_C(v) __uint_c(v, __int32_c_suffix)
  390 # else
  391 #  define INT32_C(v) v
  392 #  define UINT32_C(v) v ## U
  393 # endif /* __int32_c_suffix */
  394 #endif /* __int_least32_t */
  395 
  396 
  397 #ifdef __INT24_TYPE__
  398 # ifdef __INT24_C_SUFFIX__
  399 #  define INT24_C(v) __int_c(v, __INT24_C_SUFFIX__)
  400 #  define UINT24_C(v) __uint_c(v, __INT24_C_SUFFIX__)
  401 #  define __int16_c_suffix __INT24_C_SUFFIX__
  402 #  define __int8_c_suffix  __INT24_C_SUFFIX__
  403 # else
  404 #  define INT24_C(v) v
  405 #  define UINT24_C(v) v ## U
  406 #  undef __int16_c_suffix
  407 #  undef  __int8_c_suffix
  408 # endif /* __INT24_C_SUFFIX__ */
  409 #endif /* __INT24_TYPE__ */
  410 
  411 
  412 #ifdef __INT16_TYPE__
  413 # ifdef __INT16_C_SUFFIX__
  414 #  define __int16_c_suffix __INT16_C_SUFFIX__
  415 #  define __int8_c_suffix  __INT16_C_SUFFIX__
  416 #else
  417 #  undef __int16_c_suffix
  418 #  undef  __int8_c_suffix
  419 # endif /* __INT16_C_SUFFIX__ */
  420 #endif /* __INT16_TYPE__ */
  421 
  422 #ifdef __int_least16_t
  423 # ifdef __int16_c_suffix
  424 #  define INT16_C(v) __int_c(v, __int16_c_suffix)
  425 #  define UINT16_C(v) __uint_c(v, __int16_c_suffix)
  426 # else
  427 #  define INT16_C(v) v
  428 #  define UINT16_C(v) v ## U
  429 # endif /* __int16_c_suffix */
  430 #endif /* __int_least16_t */
  431 
  432 
  433 #ifdef __INT8_TYPE__
  434 # ifdef __INT8_C_SUFFIX__
  435 #  define __int8_c_suffix __INT8_C_SUFFIX__
  436 #else
  437 #  undef  __int8_c_suffix
  438 # endif /* __INT8_C_SUFFIX__ */
  439 #endif /* __INT8_TYPE__ */
  440 
  441 #ifdef __int_least8_t
  442 # ifdef __int8_c_suffix
  443 #  define INT8_C(v) __int_c(v, __int8_c_suffix)
  444 #  define UINT8_C(v) __uint_c(v, __int8_c_suffix)
  445 # else
  446 #  define INT8_C(v) v
  447 #  define UINT8_C(v) v ## U
  448 # endif /* __int8_c_suffix */
  449 #endif /* __int_least8_t */
  450 
  451 
  452 /* C99 7.18.2.1 Limits of exact-width integer types.
  453  * C99 7.18.2.2 Limits of minimum-width integer types.
  454  * C99 7.18.2.3 Limits of fastest minimum-width integer types.
  455  *
  456  * The presence of limit macros are completely optional in C99.  This
  457  * implementation defines limits for all of the types (exact- and
  458  * minimum-width) that it defines above, using the limits of the minimum-width
  459  * type for any types that do not have exact-width representations.
  460  *
  461  * As in the type definitions, this section takes an approach of
  462  * successive-shrinking to determine which limits to use for the standard (8,
  463  * 16, 32, 64) bit widths when they don't have exact representations. It is
  464  * therefore important that the defintions be kept in order of decending
  465  * widths.
  466  *
  467  * Note that C++ should not check __STDC_LIMIT_MACROS here, contrary to the
  468  * claims of the C standard (see C++ 18.3.1p2, [cstdint.syn]).
  469  */
  470 
  471 #ifdef __INT64_TYPE__
  472 # define INT64_MAX           INT64_C( 9223372036854775807)
  473 # define INT64_MIN         (-INT64_C( 9223372036854775807)-1)
  474 # define UINT64_MAX         UINT64_C(18446744073709551615)
  475 # define __INT_LEAST64_MIN   INT64_MIN
  476 # define __INT_LEAST64_MAX   INT64_MAX
  477 # define __UINT_LEAST64_MAX UINT64_MAX
  478 # define __INT_LEAST32_MIN   INT64_MIN
  479 # define __INT_LEAST32_MAX   INT64_MAX
  480 # define __UINT_LEAST32_MAX UINT64_MAX
  481 # define __INT_LEAST16_MIN   INT64_MIN
  482 # define __INT_LEAST16_MAX   INT64_MAX
  483 # define __UINT_LEAST16_MAX UINT64_MAX
  484 # define __INT_LEAST8_MIN    INT64_MIN
  485 # define __INT_LEAST8_MAX    INT64_MAX
  486 # define __UINT_LEAST8_MAX  UINT64_MAX
  487 #endif /* __INT64_TYPE__ */
  488 
  489 #ifdef __INT_LEAST64_MIN
  490 # define INT_LEAST64_MIN   __INT_LEAST64_MIN
  491 # define INT_LEAST64_MAX   __INT_LEAST64_MAX
  492 # define UINT_LEAST64_MAX __UINT_LEAST64_MAX
  493 # define INT_FAST64_MIN    __INT_LEAST64_MIN
  494 # define INT_FAST64_MAX    __INT_LEAST64_MAX
  495 # define UINT_FAST64_MAX  __UINT_LEAST64_MAX
  496 #endif /* __INT_LEAST64_MIN */
  497 
  498 
  499 #ifdef __INT56_TYPE__
  500 # define INT56_MAX           INT56_C(36028797018963967)
  501 # define INT56_MIN         (-INT56_C(36028797018963967)-1)
  502 # define UINT56_MAX         UINT56_C(72057594037927935)
  503 # define INT_LEAST56_MIN     INT56_MIN
  504 # define INT_LEAST56_MAX     INT56_MAX
  505 # define UINT_LEAST56_MAX   UINT56_MAX
  506 # define INT_FAST56_MIN      INT56_MIN
  507 # define INT_FAST56_MAX      INT56_MAX
  508 # define UINT_FAST56_MAX    UINT56_MAX
  509 # define __INT_LEAST32_MIN   INT56_MIN
  510 # define __INT_LEAST32_MAX   INT56_MAX
  511 # define __UINT_LEAST32_MAX UINT56_MAX
  512 # define __INT_LEAST16_MIN   INT56_MIN
  513 # define __INT_LEAST16_MAX   INT56_MAX
  514 # define __UINT_LEAST16_MAX UINT56_MAX
  515 # define __INT_LEAST8_MIN    INT56_MIN
  516 # define __INT_LEAST8_MAX    INT56_MAX
  517 # define __UINT_LEAST8_MAX  UINT56_MAX
  518 #endif /* __INT56_TYPE__ */
  519 
  520 
  521 #ifdef __INT48_TYPE__
  522 # define INT48_MAX           INT48_C(140737488355327)
  523 # define INT48_MIN         (-INT48_C(140737488355327)-1)
  524 # define UINT48_MAX         UINT48_C(281474976710655)
  525 # define INT_LEAST48_MIN     INT48_MIN
  526 # define INT_LEAST48_MAX     INT48_MAX
  527 # define UINT_LEAST48_MAX   UINT48_MAX
  528 # define INT_FAST48_MIN      INT48_MIN
  529 # define INT_FAST48_MAX      INT48_MAX
  530 # define UINT_FAST48_MAX    UINT48_MAX
  531 # define __INT_LEAST32_MIN   INT48_MIN
  532 # define __INT_LEAST32_MAX   INT48_MAX
  533 # define __UINT_LEAST32_MAX UINT48_MAX
  534 # define __INT_LEAST16_MIN   INT48_MIN
  535 # define __INT_LEAST16_MAX   INT48_MAX
  536 # define __UINT_LEAST16_MAX UINT48_MAX
  537 # define __INT_LEAST8_MIN    INT48_MIN
  538 # define __INT_LEAST8_MAX    INT48_MAX
  539 # define __UINT_LEAST8_MAX  UINT48_MAX
  540 #endif /* __INT48_TYPE__ */
  541 
  542 
  543 #ifdef __INT40_TYPE__
  544 # define INT40_MAX           INT40_C(549755813887)
  545 # define INT40_MIN         (-INT40_C(549755813887)-1)
  546 # define UINT40_MAX         UINT40_C(1099511627775)
  547 # define INT_LEAST40_MIN     INT40_MIN
  548 # define INT_LEAST40_MAX     INT40_MAX
  549 # define UINT_LEAST40_MAX   UINT40_MAX
  550 # define INT_FAST40_MIN      INT40_MIN
  551 # define INT_FAST40_MAX      INT40_MAX
  552 # define UINT_FAST40_MAX    UINT40_MAX
  553 # define __INT_LEAST32_MIN   INT40_MIN
  554 # define __INT_LEAST32_MAX   INT40_MAX
  555 # define __UINT_LEAST32_MAX UINT40_MAX
  556 # define __INT_LEAST16_MIN   INT40_MIN
  557 # define __INT_LEAST16_MAX   INT40_MAX
  558 # define __UINT_LEAST16_MAX UINT40_MAX
  559 # define __INT_LEAST8_MIN    INT40_MIN
  560 # define __INT_LEAST8_MAX    INT40_MAX
  561 # define __UINT_LEAST8_MAX  UINT40_MAX
  562 #endif /* __INT40_TYPE__ */
  563 
  564 
  565 #ifdef __INT32_TYPE__
  566 # define INT32_MAX           INT32_C(2147483647)
  567 # define INT32_MIN         (-INT32_C(2147483647)-1)
  568 # define UINT32_MAX         UINT32_C(4294967295)
  569 # define __INT_LEAST32_MIN   INT32_MIN
  570 # define __INT_LEAST32_MAX   INT32_MAX
  571 # define __UINT_LEAST32_MAX UINT32_MAX
  572 # define __INT_LEAST16_MIN   INT32_MIN
  573 # define __INT_LEAST16_MAX   INT32_MAX
  574 # define __UINT_LEAST16_MAX UINT32_MAX
  575 # define __INT_LEAST8_MIN    INT32_MIN
  576 # define __INT_LEAST8_MAX    INT32_MAX
  577 # define __UINT_LEAST8_MAX  UINT32_MAX
  578 #endif /* __INT32_TYPE__ */
  579 
  580 #ifdef __INT_LEAST32_MIN
  581 # define INT_LEAST32_MIN   __INT_LEAST32_MIN
  582 # define INT_LEAST32_MAX   __INT_LEAST32_MAX
  583 # define UINT_LEAST32_MAX __UINT_LEAST32_MAX
  584 # define INT_FAST32_MIN    __INT_LEAST32_MIN
  585 # define INT_FAST32_MAX    __INT_LEAST32_MAX
  586 # define UINT_FAST32_MAX  __UINT_LEAST32_MAX
  587 #endif /* __INT_LEAST32_MIN */
  588 
  589 
  590 #ifdef __INT24_TYPE__
  591 # define INT24_MAX           INT24_C(8388607)
  592 # define INT24_MIN         (-INT24_C(8388607)-1)
  593 # define UINT24_MAX         UINT24_C(16777215)
  594 # define INT_LEAST24_MIN     INT24_MIN
  595 # define INT_LEAST24_MAX     INT24_MAX
  596 # define UINT_LEAST24_MAX   UINT24_MAX
  597 # define INT_FAST24_MIN      INT24_MIN
  598 # define INT_FAST24_MAX      INT24_MAX
  599 # define UINT_FAST24_MAX    UINT24_MAX
  600 # define __INT_LEAST16_MIN   INT24_MIN
  601 # define __INT_LEAST16_MAX   INT24_MAX
  602 # define __UINT_LEAST16_MAX UINT24_MAX
  603 # define __INT_LEAST8_MIN    INT24_MIN
  604 # define __INT_LEAST8_MAX    INT24_MAX
  605 # define __UINT_LEAST8_MAX  UINT24_MAX
  606 #endif /* __INT24_TYPE__ */
  607 
  608 
  609 #ifdef __INT16_TYPE__
  610 #define INT16_MAX            INT16_C(32767)
  611 #define INT16_MIN          (-INT16_C(32767)-1)
  612 #define UINT16_MAX          UINT16_C(65535)
  613 # define __INT_LEAST16_MIN   INT16_MIN
  614 # define __INT_LEAST16_MAX   INT16_MAX
  615 # define __UINT_LEAST16_MAX UINT16_MAX
  616 # define __INT_LEAST8_MIN    INT16_MIN
  617 # define __INT_LEAST8_MAX    INT16_MAX
  618 # define __UINT_LEAST8_MAX  UINT16_MAX
  619 #endif /* __INT16_TYPE__ */
  620 
  621 #ifdef __INT_LEAST16_MIN
  622 # define INT_LEAST16_MIN   __INT_LEAST16_MIN
  623 # define INT_LEAST16_MAX   __INT_LEAST16_MAX
  624 # define UINT_LEAST16_MAX __UINT_LEAST16_MAX
  625 # define INT_FAST16_MIN    __INT_LEAST16_MIN
  626 # define INT_FAST16_MAX    __INT_LEAST16_MAX
  627 # define UINT_FAST16_MAX  __UINT_LEAST16_MAX
  628 #endif /* __INT_LEAST16_MIN */
  629 
  630 
  631 #ifdef __INT8_TYPE__
  632 # define INT8_MAX            INT8_C(127)
  633 # define INT8_MIN          (-INT8_C(127)-1)
  634 # define UINT8_MAX          UINT8_C(255)
  635 # define __INT_LEAST8_MIN    INT8_MIN
  636 # define __INT_LEAST8_MAX    INT8_MAX
  637 # define __UINT_LEAST8_MAX  UINT8_MAX
  638 #endif /* __INT8_TYPE__ */
  639 
  640 #ifdef __INT_LEAST8_MIN
  641 # define INT_LEAST8_MIN   __INT_LEAST8_MIN
  642 # define INT_LEAST8_MAX   __INT_LEAST8_MAX
  643 # define UINT_LEAST8_MAX __UINT_LEAST8_MAX
  644 # define INT_FAST8_MIN    __INT_LEAST8_MIN
  645 # define INT_FAST8_MAX    __INT_LEAST8_MAX
  646 # define UINT_FAST8_MAX  __UINT_LEAST8_MAX
  647 #endif /* __INT_LEAST8_MIN */
  648 
  649 /* Some utility macros */
  650 #define  __INTN_MIN(n)  __stdint_join3( INT, n, _MIN)
  651 #define  __INTN_MAX(n)  __stdint_join3( INT, n, _MAX)
  652 #define __UINTN_MAX(n)  __stdint_join3(UINT, n, _MAX)
  653 #define  __INTN_C(n, v) __stdint_join3( INT, n, _C(v))
  654 #define __UINTN_C(n, v) __stdint_join3(UINT, n, _C(v))
  655 
  656 /* C99 7.18.2.4 Limits of integer types capable of holding object pointers. */
  657 /* C99 7.18.3 Limits of other integer types. */
  658 
  659 #define  INTPTR_MIN  (-__INTPTR_MAX__-1)
  660 #define  INTPTR_MAX    __INTPTR_MAX__
  661 #define UINTPTR_MAX   __UINTPTR_MAX__
  662 #define PTRDIFF_MIN (-__PTRDIFF_MAX__-1)
  663 #define PTRDIFF_MAX   __PTRDIFF_MAX__
  664 #define    SIZE_MAX      __SIZE_MAX__
  665 
  666 /* ISO9899:2011 7.20 (C11 Annex K): Define RSIZE_MAX if __STDC_WANT_LIB_EXT1__
  667  * is enabled. */
  668 #if defined(__STDC_WANT_LIB_EXT1__) && __STDC_WANT_LIB_EXT1__ >= 1
  669 #define   RSIZE_MAX            (SIZE_MAX >> 1)
  670 #endif
  671 
  672 /* C99 7.18.2.5 Limits of greatest-width integer types. */
  673 #define  INTMAX_MIN (-__INTMAX_MAX__-1)
  674 #define  INTMAX_MAX   __INTMAX_MAX__
  675 #define UINTMAX_MAX  __UINTMAX_MAX__
  676 
  677 /* C99 7.18.3 Limits of other integer types. */
  678 #define SIG_ATOMIC_MIN __INTN_MIN(__SIG_ATOMIC_WIDTH__)
  679 #define SIG_ATOMIC_MAX __INTN_MAX(__SIG_ATOMIC_WIDTH__)
  680 #ifdef __WINT_UNSIGNED__
  681 # define WINT_MIN       __UINTN_C(__WINT_WIDTH__, 0)
  682 # define WINT_MAX       __UINTN_MAX(__WINT_WIDTH__)
  683 #else
  684 # define WINT_MIN       __INTN_MIN(__WINT_WIDTH__)
  685 # define WINT_MAX       __INTN_MAX(__WINT_WIDTH__)
  686 #endif
  687 
  688 #ifndef WCHAR_MAX
  689 # define WCHAR_MAX __WCHAR_MAX__
  690 #endif
  691 #ifndef WCHAR_MIN
  692 # if __WCHAR_MAX__ == __INTN_MAX(__WCHAR_WIDTH__)
  693 #  define WCHAR_MIN __INTN_MIN(__WCHAR_WIDTH__)
  694 # else
  695 #  define WCHAR_MIN __UINTN_C(__WCHAR_WIDTH__, 0)
  696 # endif
  697 #endif
  698 
  699 /* 7.18.4.2 Macros for greatest-width integer constants. */
  700 #define  INTMAX_C(v) __int_c(v,  __INTMAX_C_SUFFIX__)
  701 #define UINTMAX_C(v) __int_c(v, __UINTMAX_C_SUFFIX__)
  702 
  703 #endif /* __STDC_HOSTED__ */
  704 #endif /* __CLANG_STDINT_H */
