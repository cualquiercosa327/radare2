/* radare2 - LGPL - Copyright 2018 - thestr4ng3r */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static int picbaseline_op_analyze(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, CPU_MODEL *cpu) {
	op->size = 2;
	return op->size;
}

static int picbaseline_set_reg_profile(RAnal *anal) {
	const char *p =
			"=PC	pcl\n"
			"gpr	indf	.8	0	0\n"
			"gpr	tmr0	.8	1	0\n"
			"gpr	pcl		.8	2	0\n";

	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_picbaseline = {
	.name = "picbaseline",
	.desc = "PIC Baseline code analysis plugin",
	.license = "LGPL3",
	.arch = "picbaseline",
	.esil = true,
	.bits = 8,
	.op = &picbaseline_op_analyze,
	.set_reg_profile = &picbaseline_set_reg_profile
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_picbaseline,
	.version = R2_VERSION
};
#endif