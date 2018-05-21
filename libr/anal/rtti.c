/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, thestr4ng3r */

#include "r_anal.h"

R_API void r_anal_rtti_print_at_vtable(RAnal *anal, ut64 addr, int flags) {
	bool use_json = (flags & R_ANAL_RTTI_PRINT_FLAG_JSON) != 0;
	if (use_json) {
		r_cons_print ("[");
	}

	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	if (context.abi == R_ANAL_CPP_ABI_MSVC) {
		r_anal_rtti_msvc_print_at_vtable (&context, addr, flags);
	} else {
		r_anal_rtti_itanium_print_at_vtable (&context, addr, flags);
	}

	if (use_json) {
		r_cons_print ("]\n");
	}
}

static void rtti_msvc_print_all(RVTableContext *context, int flags) {
	bool use_json = (flags & R_ANAL_RTTI_PRINT_FLAG_JSON) != 0;
	bool json_first = true;
	if (use_json) {
		r_cons_print ("[");
	}

	r_cons_break_push (NULL, NULL);
	RList *vtables = r_anal_vtable_search (context);
	RListIter *vtableIter;
	RVTableInfo *table;

	if (vtables) {
		r_list_foreach (vtables, vtableIter, table) {
			if (r_cons_is_breaked ()) {
				break;
			}

			if (use_json) {
				if (json_first) {
					json_first = false;
				} else {
					r_cons_print (",");
				}
			}
			r_anal_rtti_msvc_print_at_vtable (context, table->saddr, flags);
			if (!use_json) {
				r_cons_print ("\n");
			}
		}
	}
	r_list_free (vtables);

	if (use_json) {
		r_cons_print ("]\n");
	}

	r_cons_break_pop ();
}

static void rtti_itanium_print_all(RVTableContext *context, int flags) {
	bool use_json = (flags & R_ANAL_RTTI_PRINT_FLAG_JSON) != 0;
	bool json_first = true;
	if (use_json) {
		r_cons_print ("[");
	}

	r_cons_break_push (NULL, NULL);
	RList *vtables = r_anal_vtable_search (context);
	RListIter *vtableIter;
	RVTableInfo *table;

	if (vtables) {
		r_list_foreach (vtables, vtableIter, table) {
			if (r_cons_is_breaked ()) {
				break;
			}

			if (use_json) {
				if (json_first) {
					json_first = false;
				} else {
					r_cons_print (",");
				}
			}
			r_anal_rtti_itanium_print_at_vtable (context, table->saddr, flags);
			if (!use_json) {
				r_cons_print ("\n");
			}
		}
	}
	r_list_free (vtables);

	if (use_json) {
		r_cons_print ("]\n");
	}

	r_cons_break_pop ();
}

R_API void r_anal_rtti_print_all(RAnal *anal, int flags) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);
	if (context.abi == R_ANAL_CPP_ABI_MSVC) {
		rtti_msvc_print_all (&context, flags);
	} else {
		rtti_itanium_print_all (&context, flags);
	}
}
