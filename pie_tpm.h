#include "pie.h"
#include <linux/module.h>
#include <linux/tpm.h>
#include <linux/rculist.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/file.h>
#include <linux/err.h>


#define TPM_CHIP_NUM TPM_ANY_NUM
//Assume pcr 12 as storage slot
#define TPM_PCR_NUM 12


static int pie_pcr_extend(const u8 *hash);
static int pie_pcr_read(u8 *res_buf);
static int pie_calc_hash(struct file *file, char *digest);
static int pie_calc_list_hash(void *list, char *digest);
