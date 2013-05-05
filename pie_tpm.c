#include "pie_tpm.h"


static int pie_pcr_extend(const u8 *hash)
{
    int result;

    result = tpm_pcr_extend(TPM_ANY_NUM, TPM_PCR_NUM, hash);

    if(result != 0)
    {
        pr_err("PIE_PCR_EXTEND: error TPM communication");
    }
    return result;
}

static int pie_pcr_read(u8 *res_buf)
{
    if(tpm_pcr_read(TPM_ANY_NUM, TPM_PCR_NUM, res_buf) != 0)
    {
        pr_err("PIE_PCR_READ: error TPM communication");
    }
}

//Calc file SHA1 Hash

static int pie_calc_hash(struct file *file, char *digest)
{

}

static int pie_calc_list_hash(void *list, char *digest)
{

}



