##! Adapts scan.bro to work on cluster settings. This mimics the 
##! default 1.5 configuration as installed by BroControl.

module Scan;

@if ( Cluster::is_enabled() )

redef addr_scan_trigger = 3;  
redef ignore_scanners_threshold = 500; 

redef pre_distinct_peers &read_expire = 12hrs;

redef distinct_backscatter_peers &create_expire = 5hrs;
redef distinct_peers &create_expire = 5hrs;
redef distinct_ports &create_expire = 5hrs;
redef distinct_low_ports &create_expire = 5hrs;
redef possible_scan_sources &create_expire = 5hrs;

redef distinct_backscatter_peers &synchronized;
redef distinct_peers &persistent &synchronized;
redef accounts_tried &persistent &synchronized;
redef shut_down_thresh_reached &synchronized;
redef rb_idx &synchronized;
redef rps_idx &synchronized;
redef rops_idx &synchronized;
redef rpts_idx &synchronized;
redef rat_idx &synchronized;
redef rrat_idx &synchronized;

@if ( Cluster::local_node_type() == Cluster::PROXY )
redef Notice::ignored_types += { ScanSummary };
@endif

@endif
