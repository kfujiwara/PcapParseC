#define DEF_STRUCT \
	int total; /* 4 */ \


/* summary   4 i_total */
/* summary   5 num_total */

#define DEF_FORMAT "%d,"
#define DEF_PRINTFVAR(E) E->total

#define DEF_LABEL "total,"
#define DEF_SCAN(H) \
	H->total = getint(p, &p, &error, 1); \


#define DEF_SCAN_COUNTER 2
#define DEF_MERGE(D,S) \
	D->total += S->total; \


#define DEF_SUMMARY_VAR Var(total);
#define DEF_SUMMARY_FORMAT "%d,%lld,"
	// 4
#define DEF_SUMMARY_LABELS "i_total,num_total"
#define DEF_SUMMARY_PRINTVAR(X) (X)->i_total,(X)->num_total
#define DEF_SUMMARY_COUNTUP CountUp_NonZero(total);
