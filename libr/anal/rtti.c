/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, thestr4ng3r */

#include "r_anal.h"

R_API void r_anal_print_rtti (RAnal *anal) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	r_anal_rtti_msvc_parse (&context);
}
