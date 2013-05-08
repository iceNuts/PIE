#include <linux/module.h>
#include <linux/rculist.h>
#include "pie.h"
#include "pie_tpm.h"

//A list as sha1 key-value pair hash table
//Use RCU mechanism to gurantee write-read collision

//Mutex lock vs Spin lock ? The previous would make others sleep then waken up by alert
//But the latter would keep others request for control over and over again.
//Mutex is fit for pcr extend as it takes a long time.

//Definitions
struct  pie_table
{
    /* data */
    struct list_head list;
};

struct pie_table_entry
{
    /* data */
    u8 *digest;
    struct list_head latter;
};


//Lookup function
static int pie_table_lookup(u8 *digest);
//Add entry
int pie_add_entry(u8 *digest);