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
        return -1;
    }
    return 0;
}

//Calc file SHA1 Hash

int init_hash(struct hash_desc *desc)
{
    int rc;

    desc->tfm = crypto_alloc_hash("SHA1", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(desc->tfm)) 
    {
        pr_err("INIT_HASH: hash load failure");
        rc = PTR_ERR(desc->tfm);
        return rc;
    }

    desc->flags = 0;
    rc = crypto_hash_init(desc);
    if (rc)
        crypto_free_hash(desc->tfm);
    return rc;
}

static int pie_calc_hash(struct file *file, char *digest)
{
    struct hash_desc desc;
    struct scatterlist sg[1];
    loff_t i_size, offset = 0;
    char *rbuf;
    int rc;

    rc = init_hash(&desc);
    if (rc != 0)
        return rc;

    rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!rbuf) {
        rc = -ENOMEM;
        goto out;
    }
    i_size = i_size_read(file->f_dentry->d_inode);
    while (offset < i_size) {
        int rbuf_len;

        rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
        if (rbuf_len < 0) {
            rc = rbuf_len;
            break;
        }
        if (rbuf_len == 0)
            break;
        offset += rbuf_len;
        sg_init_one(sg, rbuf, rbuf_len);

        rc = crypto_hash_update(&desc, sg, rbuf_len);
        if (rc)
            break;
    }
    kfree(rbuf);
    if (!rc)
        rc = crypto_hash_final(&desc, digest);
out:
    crypto_free_hash(desc.tfm);
    return rc;
}

//Calc the hash of a list

static int pie_calc_list_hash(int list_len void *list, char *digest)
{
    struct hash_desc desc;
    struct scatterlist sg[1];
    int rc;

    rc = init_desc(&desc);
    if (rc != 0)
        return rc;

    sg_init_one(sg, list, list_len);
    rc = crypto_hash_update(&desc, sg, list_len);
    if (!rc)
        rc = crypto_hash_final(&desc, digest);
    crypto_free_hash(desc.tfm);
    return rc;
}



