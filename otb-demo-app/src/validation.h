/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_DEMO_VALIDATION_H
#define OTB_DEMO_VALIDATION_H

gboolean otb_validation_validate_not_blank(GtkEntry *entry);
gboolean otb_validation_validate_equal(GtkEntry *entry1, GtkEntry *entry2);
gboolean otb_validation_validate_local_crypto_unlock(GtkEntry *entry);

#endif
