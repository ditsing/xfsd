#include "process.h"
static struct process process_current = { 0 };
const struct process *current = &process_current;
