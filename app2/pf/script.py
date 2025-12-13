# import os
# from pf import pfctl_table_del_addr_list


# dev = os.open("/dev/pf", os.O_RDWR)

# try:
#     pfctl_table_del_addr_list(dev, "second", ["10.0.4.15", "10.0.4.1"],  0)
# finally:
#     os.close(dev)