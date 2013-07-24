#!/usr/local/bin/perl

require v5.10.1;

use warnings;
use strict;
use feature "switch";

use Carp;
use Data::Dumper;

use POSIX;
use IO::File;
use Getopt::Long;
use Pod::Usage;
use Parse::RecDescent;

use constant {
	DEBUG => 0,

	MY_VERSION => 'v0.4.0',
	MY_NAME => 'router2dns.pl',

	VERBOSE_PHASE => 1,
	VERBOSE_PHASE_DETAIL => 2,
	VERBOSE_ZONE => 2,
	VERBOSE_INTERFACE => 3,
	VERBOSE_DEVICE => 3,
	VERBOSE_IP => 4,
	VERBOSE_RR => 4,
};

use constant {
	MAINIF_INTACT => 0,
	MAINIF_HOSTNAME => 1,
	MAINIF_CNAME => 2,

	MAINIFRR_DEFAULT => 0,
	MAINIF_DEFAULT => 'lo0',

	FWDZ_OVERRIDE_DEFAULT => 1,

	REGISTER_UNNUMBERED_DEFAULT => 0,

	ENTRY_START => 0,
	ENTRY_A => 1,
	ENTRY_AAAA => 2,
	ENTRY_CNAME => 3,
	ENTRY_PTR => 4,

	DEV_IOS_ROUTER => 0,
	DEV_JUNOS_ROUTER => 1,
	DEV_IOS_HOST => 2,

	RZ_SORT_BY_DEVICE => 0,
	RZ_SORT_BY_ADDRESS => 1,

	RZ_SORT_DEFAULT => 0,
};

# zone file RR types belonging to ENTRY_x
use constant RR_TYPE => ( '', 'A', 'AAAA', 'CNAME', 'PTR' );

my $reverse_zones = [];
my $forward_zones = [];
my $devices = [];
my $address_restrictions_list = undef;
my $vrf_restrictions_list = undef;
my $int_restrictions_list = undef;
my $verbose_level = 1;
my $omit_log = 0;
my $include_log = 0;

my $Parsed_Cfg;

my $Options = {
	'interface-types' => {
		# keys must be lowercase here
		# (keys read from router2dns.conf are converted to lowercase, as well as
		#  names read from router config files)
		'loopback' => 'lo',
		'ethernet' => 'e',
		'fastethernet' => 'fe',
		'gigabitethernet' => 'ge',
		'tengigabitethernet' => 'xge',
		'tengige' => 'xge',
		'hundredgige' => 'hge',
		'vlan' => 'vl',
		'serial' => 's',
		'tunnel' => 'tun',
		'port-channel' => 'be',
		'bundle-ether' => 'be'
	},
	'interface-subs' => [],
};

my $config_grammar_in = q{

  ConfigFile: <rulevar: local $cfg = {}>
  ConfigFile: <rulevar: local @stack>
  ConfigFile:
    { push @stack, $cfg }
    (   OptionsBlock['single'] { $cfg->{'options'} = $item[-1] }
      | RestrictionsBlock['single'] { $cfg->{'restrictions'} = $item[-1] }
      | DevicesBlock['single'] { $cfg->{'devices'} = $item[-1] }
      | ForwardZoneBlock { push @{$cfg->{'forward-zones'}}, $item[-1] }
      | ReverseZoneBlock { push @{$cfg->{'reverse-zones'}}, $item[-1] }
    )(s) /\Z/ { $return = $cfg }
    | <error>

  BLOCK_START( RestrictionsBlock, restrictions )
    (   AddressListBlock BLOCK_SINGLE_STORE( address-list )
      | VrfListBlock BLOCK_SINGLE_STORE( vrf-list )
      | IntListBlock BLOCK_SINGLE_STORE( interface-list )
    )(s?)
  BLOCK_END

  BLOCK_START( AddressListBlock, address-list )
    (	AddressListItem BLOCK_MULTI_STORE( entries )
    )(s?)
  BLOCK_END  

  AddressListItem: IncludePrefixItem | ExcludePrefixItem

  ITEM_START( IncludePrefixItem, include )
    PrefixStringVal ITEM_END

  ITEM_START( ExcludePrefixItem, exclude )
    PrefixStringVal ITEM_END


  BLOCK_START( VrfListBlock, vrf-list )
    (   StringListItem BLOCK_MULTI_STORE( entries )
    )(s?)
  BLOCK_END  

  BLOCK_START( IntListBlock, interface-list )
    (   StringListItem BLOCK_MULTI_STORE( entries )
    )(s?)
  BLOCK_END  

  StringListItem: IncludeStringItem | ExcludeStringItem

  ITEM_START( IncludeStringItem, include )
    StringVal ITEM_END

  ITEM_START( ExcludeStringItem, exclude )
    StringVal ITEM_END


  BLOCK_START( DevicesBlock, devices )
    (   IosRouterBlock BLOCK_MULTI_STORE( ios-routers )
      | IosHostBlock BLOCK_MULTI_STORE( ios-hosts )
      | JunosRouterBlock BLOCK_MULTI_STORE( junos-routers )
    )(s)
  BLOCK_END

  BLOCK_START( ForwardZoneBlock, forward-zone )
    (   ZoneNameItem BLOCK_SINGLE_STORE( name )
      | FileItem BLOCK_SINGLE_STORE( file )
    )(s)
  BLOCK_END

  BLOCK_START( IosRouterBlock, ios-routers )
    (   SnmpCommunityItem BLOCK_SINGLE_STORE( snmp-community )
      | ConfigListItem BLOCK_MULTI_STORE( config-list-file )
      | ConfigItem BLOCK_MULTI_STORE( config )
      | MainIfRrsItem BLOCK_SINGLE_STORE( main-interface-rrs )
      | MainIfItem BLOCK_SINGLE_STORE( main-interface )
      | ForwardZoneItem BLOCK_SINGLE_STORE( forward-zone )
      | ForwardZoneOverrideItem BLOCK_SINGLE_STORE( forward-zone-override )
    )(s?)
  BLOCK_END

  BLOCK_START( IosHostBlock, ios-hosts )
    (   SnmpCommunityItem BLOCK_SINGLE_STORE( snmp-community )
      | ConfigListItem BLOCK_MULTI_STORE( config-list-file )
      | ConfigItem BLOCK_MULTI_STORE( config )
      | ForwardZoneItem BLOCK_SINGLE_STORE( forward-zone )
      | ForwardZoneOverrideItem BLOCK_SINGLE_STORE( forward-zone-override )
    )(s?)
  BLOCK_END

  BLOCK_START( JunosRouterBlock, junos-routers )
    (   SnmpCommunityItem BLOCK_SINGLE_STORE( snmp-community )
      | ConfigListItem BLOCK_MULTI_STORE( config-list-file )
      | ConfigItem BLOCK_MULTI_STORE( config )
    )(s?)
  BLOCK_END


  ITEM_START( ConfigItem, config )
    FileNameVal ITEM_END

  ITEM_START( ConfigListItem, config-list-file )
    FileNameVal ITEM_END

  ITEM_START( SnmpCommunityItem, snmp-community )
    SnmpCommunityVal ITEM_END

  SnmpCommunityVal: StringVal
    | <error:Invalid SNMP community string>

  ITEM_START( MainIfItem, main-interface )
    StringVal ITEM_END

  ITEM_START( ForwardZoneItem, forward-zone )
    ZoneNameStringVal ITEM_END

  ITEM_START( ForwardZoneOverrideItem, forward-zone-override )
    BoolVal ITEM_END


  BLOCK_START( ReverseZoneBlock, reverse-zone )
    (   ZonePrefixItem BLOCK_SINGLE_STORE( prefix )
      | FileItem BLOCK_SINGLE_STORE( file )
      | DelegatedBlock BLOCK_SINGLE_STORE( delegated )
    )(s)
  BLOCK_END

  BLOCK_START( DelegatedBlock, delegated )
    (   ZoneNameListItem BLOCK_MULTI_STORE( name-list-file )
      | ZoneNameItem BLOCK_MULTI_STORE( name )
      | ZonePrefixListItem BLOCK_MULTI_STORE( prefix-list-file )
      | ZonePrefixItem BLOCK_MULTI_STORE( prefix )
    )(s?)
  BLOCK_END


  BLOCK_START( OptionsBlock, options )
    (   ConfigBaseDirItem BLOCK_SINGLE_STORE( config-base-dir )
      | OutputDirItem BLOCK_SINGLE_STORE( output-dir )
      | InterfaceTypeBlock BLOCK_MULTI_STORE( interface-type )
      | InterfaceSubsBlock BLOCK_MULTI_STORE( interface-substitution )
      | RzSortByItem BLOCK_SINGLE_STORE( reverse-zone-sort-by )
      | RegisterUnnumberedItem BLOCK_SINGLE_STORE( register-unnumbered )
    )(s?)
  BLOCK_END

  ITEM_START( ConfigBaseDirItem, config-base-dir )
    DirNameVal ITEM_END

  ITEM_START( OutputDirItem, output-dir )
    DirNameVal ITEM_END

  ITEM_START( RzSortByItem, reverse-zone-sort-by )
    RzSortByVal ITEM_END

  ITEM_START( RegisterUnnumberedItem, register-unnumbered )
    BoolVal ITEM_END
    

  BLOCK_START( InterfaceTypeBlock, interface-type )
    (   InterfaceTypeConfigNameItem BLOCK_MULTI_STORE( config-name )
      | InterfaceTypeDnsNameItem BLOCK_SINGLE_STORE( dns-name )
    )(s?)
  BLOCK_END

  ITEM_START( InterfaceTypeConfigNameItem, config-name )
    StringVal ITEM_END

  ITEM_START( InterfaceTypeDnsNameItem, dns-name )
    StringVal ITEM_END


  BLOCK_START( InterfaceSubsBlock, interface-substitution )
    (   InterfaceSubsPatternItem BLOCK_SINGLE_STORE( pattern )
      | InterfaceSubsSubstitutionItem BLOCK_SINGLE_STORE( substitution )
    )(s?)
  BLOCK_END

  ITEM_START( InterfaceSubsPatternItem, pattern )
    StringVal ITEM_END

  ITEM_START( InterfaceSubsSubstitutionItem, substitution )
    StringVal ITEM_END


  ITEM_START( MainIfRrsItem, main-interface-rrs )
    MainIfRrsVal ITEM_END



  ITEM_START( ZoneNameItem, name )
    ZoneNameStringVal ITEM_END

  ITEM_START( ZoneNameListItem, name-list-file )
    FileNameVal ITEM_END

  ITEM_START( ZonePrefixItem, prefix )
    PrefixStringVal ITEM_END

  ITEM_START( ZonePrefixListItem, prefix-list-file )
    FileNameVal ITEM_END


  ZoneNameStringVal: StringVal
    { ( $item[1] =~ /^([A-Za-z0-9\-]+\.)*[A-Za-z0-9\-]+$/ ) ? $item[1] : undef }
    | <error:Invalid zone name value>

  PrefixStringVal: StringVal
    { ( $item[1] =~ /[0-9A-Fa-f.:]+\/[0-9]+/ ) ? $item[1] : undef }
    | <error:Invalid prefix value>


  ITEM_START( FileItem, file )
    FileNameVal ITEM_END

  FileNameVal: StringVal
    | <error:Invalid file name>

  DirNameVal: StringVal
    { ( $item[1] =~ m|/$| ) ? $item[1] : undef }
    | <error:Invalid directory name>

  StringVal: QuotedStringVal | BareStringVal

  QuotedStringVal: /"(\\\\[^\\n\\r]|[^\\n\\r"\\\\])*"/
  {
    $item[1] =~ s/\\\\(.)/\\1/g;
    substr( $item[1], 1, -1 );
  }

  BareStringVal: /(\\\\[^\\n\\r]|[^\\n\\r\\s;{}"])+/
  {
    $item[1] =~ s/\\\\(.)/\\1/g;
    $item[1];
  }

  MainIfRrsVal: /intact/i { 0 } | /hostname/i { 1 } | /cname-of-hostname/i { 2 }

  RzSortByVal: /device/i { 0 } | /address/i { 1 }

  BoolVal: TrueVal { 1 } | FalseVal { 0 }
  TrueVal: /true/i | /yes/i
  FalseVal: /false/i | /no/i

  BlockStart: '{'
  BlockEnd: /};?/
  ItemEnd: ';'
};

sub config_grammar_preproc($$) {
  my $text = shift;
  my $file = shift;

  $text =~ s/BLOCK_START\(\s*(\S+)\s*,\s*(\S+)\s*\)/$1: <rulevar: local \$block = {}>
  $1: { push \@stack, \$block }
    '$2'
    { if(( \$arg[0] eq 'single' ) && ( exists \$stack[-2]->{'$2'} )) {
        printf "Warning: Repeated $1.\\n  file '$file', line \$prevline\\n";
      }
      undef \@arg; 1
    }
    <commit> { \$block->{'cfg_line'} = \$prevline; \$block->{'cfg_file'} = '$file' }
    BlockStart/g;

  $text =~ s/BLOCK_END/  BlockEnd { pop \@stack; \$return = \$block }
    | { pop \@stack } <reject>
    | <error?> <reject>/g;

  $text =~ s/\s+BLOCK_SINGLE_STORE\(\s*(\S+)\s*\)/['single'] { \$block->{'$1'} = \$item[-1] }/g;

  $text =~ s/BLOCK_MULTI_STORE\(\s*(\S+)\s*\)/{ push \@{\$block->{'$1'}}, \$item[-1] }/g;

  $text =~ s|ITEM_START\(\s*(\S+)\s*,\s*(\S+)\s*\)|$1: /$2\\s/
    { if(( \$arg[0] eq 'single' ) && ( exists \$stack[-1]->{'$2'} )) {
        printf "Warning: Repeated $1.\\n  file '$file', line \$prevline\\n";
      }
      undef \@arg; 1
    }
    <commit>|g;

  $text =~ s/ITEM_END/ItemEnd
    { \$return = { 'cfg_line' => \$prevline, 'cfg_file' => '$file', 
    		   'keyword' => substr( \$item[-5], 0, -1 ), 'val' => \$item[-2] } }
    | <error?> <reject>/g;

  return $text;
}

####################################################################################
# config_read( $file_name )
####################################################################################
#
# Read config file into memory. Line by line, remove comments.
#
sub config_read($) {
  my $file_name = shift;
  my $fh = new IO::File;
  my $line;
  my $text;

  $fh->open( "< $file_name" ) or die( "\nError: Cannot open config file '$file_name'.\n" );
  while( defined( $line = $fh->getline )) {
    chomp $line;
    # drop comments
    $line =~ /^((\\.|"(\\.|[^"\\])*"|[^"\\#])*)(#|$)/;
    $text .= $1 . "\n";
  }

  return $text;
}

####################################################################################
# expand_list( $enclosing_block, $list_type )
####################################################################################
#
# Walk through a block of parsed configuration, and expand "xyz-list-file" configuration
# parameters to (multiple) "xyz" parameters.
#
sub expand_list($$) {
  my $p = shift;
  my $list_type = shift;

  if( exists( $p->{ $list_type . '-list-file' } )) {
    foreach my $q ( @{ $p->{ $list_type . '-list-file' }} ) {
      my $fh = new IO::File;
      my $fn = $q->{ 'val' };
      my $line_num = 1;
      my $line;

      $fh->open( "< $fn" ) or
	die( "\nError: Cannot open $list_type-list-file '$fn'.\n" .
		"  file '$q->{ 'cfg_file' }', line $q->{ 'cfg_line' }\n" );
      while( defined( $line = $fh->getline )) {
	chomp $line;
	( $line =~ /^\s*"((\\.|[^"\\])+)"\s*(#|$)/ ) or
	( $line =~ /^\s*((\\.|[^"\\#\s])*)\s*(#|$)/ ) or
	die( "\nError: Invalid string '$line'.\n  file '$fn', line $line_num\n" );
	$line = $1;
	$line =~ s/\\(.)/$1/g;	# remove backslash escape characters

	if( $line ne '' ) {
	  push @{ $p->{ $list_type }},
		{ 'val' => "$line", 'cfg_line' => $line_num, 'cfg_file' => $fn };
	}

	$line_num++;
      }
      undef $fh;
    }
  }
}

sub generated_message() {
  my $dt = strftime "%F %T %Z", localtime;

  return "section generated by " . MY_NAME . ' ' . MY_VERSION .  " at $dt";
}

sub is_v4_addr_str($) {
  my $addr_str = shift;

  # 4 non-negative dot separated integers, 1..3 digits each
  if( $addr_str !~ /^([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}$/ ) {
    return 0;
  }

  my @addr_arr = split( /\./, $addr_str );
  for( my $n = 0; $n < 4; $n++ ) {
    if( $addr_arr[$n] > 255 ) { return 0; }
  } 
  return 1;
}

sub canonize_v4_addr_str {
  my $addr_str = shift;
  
  if( !is_v4_addr_str( $addr_str )) {
    return undef;
  }

  my @addr_arr = split( /\./, $addr_str );

  # remove extra leading 0s
  # 0 octet represented as 00 or 000: keep the first 0 and drop the others
  $addr_str =~ s/((^|\.)0)0+(?=\.|$)/$1/g;
  # non-zero octet with leading 0: drop leading 0s
  $addr_str =~ s/(^|\.)0+(?=[1-9])/$1/g;

  return $addr_str;
}

sub is_v4_prefix_str($) {
  my $prefix_str = shift;

  my $addr_str;
  my $len_str;
  my $trash;

  ( $addr_str, $len_str, $trash ) = split( /\//, $prefix_str, 3 );
  if( defined $trash ) { return 0; }
  if( !defined $len_str || ( $len_str !~ /^[[:digit:]]+$/ )) { return 0; }
  if(( $len_str > 32 ) || ( $len_str < 0 )) { return 0; }
  return is_v4_addr_str( $addr_str );
}


sub is_v6_addr_str {
  my $addr_str = shift;
  
  # 2..7 colons, 0..4 hex digits in between colons
  if( $addr_str !~ /^([[:xdigit:]]{0,4}:){2,7}[[:xdigit:]]{0,4}$/ ) {
    return 0;
  }

  # double colons at most once
  if(( $addr_str =~ /:::/ ) ||
     ( $addr_str =~ /::.+::/ )) { return 0; }

  # TODO: leading/trailing : ???
  # leading or trailing colon must be double
  if(( $addr_str =~ /^:[[:xdigit:]]/ ) ||
     ( $addr_str =~ /[[:xdigit:]]:$/ )) { return 0; }

  # too short address without double colons
  if(( $addr_str !~ /::/ ) && (( $addr_str =~ tr/:// ) < 7 )) { return 0; }

  return 1;
}

sub expand_v6_addr_str {
  my $addr_str = shift;

  if( !is_v6_addr_str( $addr_str )) { return undef; }
  
  # expand ::
  my $col_count = ( $addr_str =~ tr/:// );
  my $fill = ':0000' x ( 8 - $col_count );
  if( $addr_str =~ s/::/$fill:/ ) {
    # insert missing leading 0
    $addr_str =~ s/^:/0000:/;
    # insert missing trailing 0
    $addr_str =~ s/:$/:0000/;
  }

  # check length
  if(( $addr_str =~ s/:/:/g ) != 7 ) { return undef; }

  # # remove extra leading 0s
  # $addr_str =~ s/((^|:)0)0+(?=:|$)/$1/g;
  # $addr_str =~ s/(^|:)0+(?=[^:])/$1/g;

  $addr_str =~ s/(^|:)([[:xdigit:]]{1})(?=:|$)/${1}000$2/g;
  $addr_str =~ s/(^|:)([[:xdigit:]]{2})(?=:|$)/${1}00$2/g;
  $addr_str =~ s/(^|:)([[:xdigit:]]{3})(?=:|$)/${1}0$2/g;

  return lc( $addr_str );
}

sub is_v6_prefix_str($) {
  my $prefix_str = shift;

  my $addr_str;
  my $len_str;
  my $trash;

  ( $addr_str, $len_str, $trash ) = split( /\//, $prefix_str, 3 );
  if( defined $trash ) { return 0; }
  if( !defined $len_str || ( $len_str !~ /^[[:digit:]]+$/ )) { return 0; }
  if(( $len_str > 128 ) || ( $len_str < 0 )) { return 0; }
  return is_v6_addr_str( $addr_str );
}

sub pack_prefix {
  my $in = shift;

  my $addr_str;
  my $prefix_len;
  my $ip_ver = 0;
  my $out;

  if( is_v4_prefix_str( $in )) {
    ( $addr_str, $prefix_len ) = split( /\//, $in );
    $ip_ver = 4;
  } elsif( is_v4_addr_str( $in )) {
    $addr_str = $in;
    $prefix_len = 32;
    $ip_ver = 4;
  } elsif( is_v6_prefix_str( $in )) {
    ( $addr_str, $prefix_len ) = split( /\//, $in );
    $addr_str = expand_v6_addr_str( $addr_str );
    $ip_ver = 6;
  } elsif( is_v6_addr_str( $in )) {
    $addr_str = expand_v6_addr_str( $in );
    $prefix_len = 128;
    $ip_ver = 6;
  } else { return undef; }

  my $p;	# packed IP address
  my $bits;	# IP address length in bits
  my $b;	# prefix, binary string

  if( $ip_ver == 4 ) {
    $bits = 32;
    $p = pack( 'C4', split( /\./, $addr_str ));
  } else {
    $bits = 128;
    $p = pack( '(H4)8', split( /:/, $addr_str ));
  }
  # get prefix as binary string, and pad it with zeros
  $b = unpack( "B$prefix_len", $p ) . '0' x ( $bits - $prefix_len );
  # pack prefix as 'C C/C', prefix_len, @address_bytes
  return pack( "C C B$bits", $prefix_len, $bits / 8, $b );
}

sub get_prefix_len($) {
  my $packed = shift;

  my ( $prefix_len ) = unpack( 'C', $packed );
  return $prefix_len;
}

sub get_address_ver($) {
  my $packed = shift;

  my @addr_bytes = unpack( 'x C/C', $packed );

  given( scalar @addr_bytes ) {
    when( 4 ) {
      return 4;
    }
    when( 16 ) {
      return 6;
    }
    default {
      return 0;
    }
  }
}

sub sprint_address($) {
  my $packed = shift;

  my $addr;
  my @addr_bytes;

  @addr_bytes = unpack( 'x C/C', $packed );

  if( scalar @addr_bytes == 4 ) {
    return sprintf( '%i.%i.%i.%i', @addr_bytes );
  } elsif( scalar @addr_bytes == 16 ) {
    my @addr_words;
    my $lsize = 0;	# size of the longest sequence of consecutive 0 words (16 bits)
    my $lstart = -1;	# start position of the longest sequence of consecutive 0 words
    my $csize = 0;	# size of the currently inspected sequence of consecutive 0 words
    my $cstart = 0;	# start position of the currently inspected seqence
    my $cpos;
    my $addr;
    for( my $n = 0; $n < 16; ) {
      $cpos = $n/2;
      $addr_words[$cpos] = $addr_bytes[$n++] * 256 + $addr_bytes[$n++];
      if( !$addr_words[$cpos] ) {
	if( !$csize ) { $cstart = $cpos };
	$csize++;
	if( $csize >= $lsize ) {
	  $lsize = $csize;
	  $lstart = $cstart;
	}
      } else { $csize = 0; }
    }
    if( $lsize > 1 ) {
      $addr = ( $lstart > 0 ) ? sprintf( '%x:' x $lstart, @addr_words ) : ':';
      my $r = 8 - ( $lstart + $lsize );
      $addr .= ( $r > 0 ) ? sprintf( ':%x' x $r, splice( @addr_words, 0 - $r )) : ':';
    } else {
      $addr = sprintf( '%x:%x:%x:%x:%x:%x:%x:%x', @addr_words );
    }
    return $addr;
  } else { return undef; }
}

sub sprint_prefix($) {
  my $packed = shift;

  return sprint_address( $packed ) . '/' . get_prefix_len( $packed );
}

sub is_ip_prefix_of($$) {
  my $shorter = shift;
  my $longer = shift;

  my ( $prefix_len_sh, @addr_bytes_sh ) = unpack( 'C C/C', $shorter );
  my ( $prefix_len_lo, @addr_bytes_lo ) = unpack( 'C C/C', $longer );

  if( scalar @addr_bytes_sh != scalar @addr_bytes_lo ) { return 0; }

  if( $prefix_len_sh > $prefix_len_lo ) { return 0; }

  my $prefix_sh = unpack( "xxB$prefix_len_sh", $shorter );
  my $prefix_lo = unpack( "xxB$prefix_len_sh", $longer );

  return $prefix_sh eq $prefix_lo;
}

sub is_prefix_eq($$) {
  my ( $p1, $p2 ) = @_;

  return unpack( 'H*', $p1 ) eq unpack( 'H*', $p2 );
}

sub prefix_cmp($$) {
  my $a1 = shift;
  my $a2 = shift;

  my ( $a1_bytes, $a1_bin ) = unpack( 'x C B*', $a1 );
  my ( $a2_bytes, $a2_bin ) = unpack( 'x C B*', $a2 );

  if( $a1_bytes != $a2_bytes ) { 
    return $a1_bytes <=> $a2_bytes;
  }

  return $a1_bin cmp $a2_bin;
}

sub rz_entry_cmp($$) {
  my $e1 = shift;
  my $e2 = shift;

  return prefix_cmp( $e1->{ 'addr' }, $e2->{ 'addr' } );
}

sub is_domain_postfix_of($$) {
  my $upper = shift;
  my $lower = shift;

  $upper =~ s/\./\\./g;

  return ( $lower =~ /(^|\.)$upper$/i );
}

sub dev_fqdn_cmp($$) {
  my $d1 = shift;
  my $d2 = shift;

  return fqdn_cmp( $d1->{ 'fqdn' }, $d2->{ 'fqdn' } );
}
####################################################################################
# insert_forward_zone( $new_forward )
####################################################################################
#
# Forward zones are sorted by their origin so that looking up a domain name results
# in the longest postfix match.
#
# insert_forward_zone inserts a forward zone description block into the list.
#
sub insert_forward_zone($) {

  my $new_forward = shift;

  my $m = scalar @$forward_zones;
  my @rest;

  # Every new zone is inserted just before the first upper zone.
  # Find the zone that is a postfix of our new one.
  for( my $n = 0; $n < $m; $n++ ) {
    if( is_domain_postfix_of( $forward_zones->[$n]->{ 'name' }, $new_forward->{ 'name' } )) {
      # Detach rest of the list.
      @rest = splice( @$forward_zones, $n );
      last;
    }
  }

  # Insert new zone.
  push( @$forward_zones, $new_forward );

  # Re-attach rest of the list (if any) after the new one.
  if( @rest ) { 
    push( @$forward_zones, @rest );
  }
}


####################################################################################
# insert_reverse_zone( $new_reverse )
####################################################################################
#
# Reverse zones are sorted by their prefix so that looking up an IP address results
# in the longest prefix match. The only rule is that prefixB must be somewhere after
# prefixA if prefixA covers prefixB. Walking through the list the first match will
# be the longest prefix match.
#
# insert_reverse_zone inserts a reverse zone description block into the list.
#
sub insert_reverse_zone($) {

  my $new_reverse = shift;

  my $m = scalar @$reverse_zones;
  my @rest;

  # Every new zone/prefix is inserted just before the first covering prerfix.
  # Find the prefix that is a (shorter) prefix of our new one.
  for( my $n = 0; $n < $m; $n++ ) {
    if( is_ip_prefix_of( $reverse_zones->[$n]->{ 'prefix' }, $new_reverse->{ 'prefix' } )) {
      # Detach rest of the list.
      @rest = splice( @$reverse_zones, $n );
      last;
    }
  }

  # Insert new prefix.
  push( @$reverse_zones, $new_reverse );

  # Re-attach rest of the list (if any) after the new one.
  if( @rest ) { 
    push( @$reverse_zones, @rest );
  }
}


####################################################################################
# prefix_of_reverse_name( $origin_prefix, $deleg_label )
####################################################################################
#
# Calculate the prefix for a given label (DNS name) of a delegation from an origin
# reverse zone.
#
# Simplified example:  prefix_of_reverse_name( 10.0.0.0/8, '4.5' ) == 10.5.4.0/24
#
sub prefix_of_reverse_name($$) {
  my $origin_prefix = shift;
  my $deleg_label = shift;

  my ( $origin_prefix_len, @origin_addr_bytes ) = unpack( 'C C/C', $origin_prefix );

  if( scalar @origin_addr_bytes == 4 ) {
    # IPv4

    # Delegation defined by DNS label is only possible if the reverse zone
    # is on an octet boundary.
    if( $origin_prefix_len % 8 ) { return undef; }

    # Check the label's syntax.
    if( $deleg_label !~ /^([[:digit:]]{1,3}\.)*[[:digit:]]{1,3}$/ ) { return undef; }

    my @label_bytes = reverse( split( /\./, $deleg_label ));
    my $label_len = scalar @label_bytes;

    # The label must not be too long.
    if( $label_len * 8 + $origin_prefix_len > 32 ) { return undef; }

    # Replace the zeros in the prefix with the reversed label.
    for( my $n = 0; $n < $label_len; $n++ ) {
      if( $label_bytes[$n] > 255 ) { return undef; }
      $origin_addr_bytes[$n + $origin_prefix_len / 8] = $label_bytes[$n];
    } 

    #return pack( 'C C C4', $origin_prefix_len + $label_len * 8, 4, @origin_addr_bytes );
    my $packed = pack( 'C C C4', $origin_prefix_len + $label_len * 8, 4, @origin_addr_bytes );
    if( DEBUG ) { print 'DEBUG:' . sprint_prefix( $packed ) . "\n"; }
    return $packed;
  }
  elsif ( scalar @origin_addr_bytes == 16 ) {
    # IPv6
    if( DEBUG ) { print "DEBUG: IPv6\n"; }
    if( $origin_prefix_len % 4 ) { return undef; }

    if( $deleg_label !~ /^([[:xdigit:]]\.)*[[:xdigit:]]$/ ) { return undef; }
    my @label_nibbles = reverse( split( /\./, lc( $deleg_label )));
    my $label_len = scalar @label_nibbles;
    if( $label_len * 4 + $origin_prefix_len > 128 ) { return undef; }

    my $origin_nibbles = $origin_prefix_len / 4;
    my $origin_addr_nibbles = unpack( "xxH$origin_nibbles", $origin_prefix );

    for( my $n = 0; $n < $label_len; $n++ ) {
      $origin_addr_nibbles .= $label_nibbles[$n];
    } 
    $origin_addr_nibbles .= '0' x ( 32 - $origin_nibbles - $label_len );

    return pack( 'C C H32', $origin_prefix_len + $label_len * 4, 16, $origin_addr_nibbles );
  }
  else { return undef; }
}

####################################################################################
# label_of_reverse_record( $origin_prefix, $addr )
####################################################################################
#
# Construct the DNS label of a reverse (PTR) record for a given $ORIGIN and the IP
# address.
#
sub label_of_reverse_record($$) {
  my $origin_prefix = shift;
  my $addr = shift;

  my $label;
  my @addr_bytes;
  my $origin_len;

  if( !is_ip_prefix_of( $origin_prefix, $addr )) {
    return undef;
  }

  $origin_len = get_prefix_len( $origin_prefix );

  @addr_bytes = unpack( 'x C/C', $addr );

  if( scalar @addr_bytes == 4 ) {
    my $bytes = 4 - POSIX::floor( $origin_len / 8 );
    if( $bytes < 1 ) { $bytes = 1; }
    return sprintf( '%i.' x ( $bytes - 1 ) . '%i', reverse @addr_bytes );
  } elsif( scalar @addr_bytes == 16 ) {
    my $digits = 32 - POSIX::floor( $origin_len / 4 );
    if( $digits < 1 ) { $digits = 1; }

    my @addr_digits;
    my $cpos = 0;
    for( my $n = 15; $cpos < $digits; $n-- ) {
      $addr_digits[$cpos++] = $addr_bytes[$n] % 16;
      $addr_digits[$cpos++] = POSIX::floor( $addr_bytes[$n] / 16 );
    }
    return sprintf( '%x.' x ( $digits - 1 ) . '%x', @addr_digits );
  } else { return undef; }
}

####################################################################################
# origin_of_reverse_zone( $origin_prefix )
####################################################################################
#
sub origin_of_reverse_zone($) {
  my $origin_prefix = shift;

  my @prefix_bytes;
  my $origin_len;
  my $origin = "";

  $origin_len = get_prefix_len( $origin_prefix );
  @prefix_bytes = unpack( 'x C/C', $origin_prefix );

  if( scalar @prefix_bytes == 4 ) {
    if( $origin_len > 24 ) {
      $origin .= sprintf( '%i/%i.', $prefix_bytes[3], $origin_len );
    }
    my $bytes = POSIX::floor( $origin_len / 8 );
    $origin .= sprintf( '%i.' x $bytes . 'in-addr.arpa.', reverse @prefix_bytes[0 .. $bytes-1] );
  } elsif( scalar @prefix_bytes == 16 ) {
    my @addr_digits;
    my $digits = POSIX::floor( $origin_len / 4 );

    if( $origin_len > 124 ) {
      $origin .= sprintf( '%x/%i.', POSIX::floor( $prefix_bytes[15] /16 ), $origin_len );
    }

    my $m = POSIX::floor(( $digits - 1 ) / 2 );
    for( my $n = $digits; $n > 0; $n-- ) {
      push @addr_digits, ( $n % 2 ) ?
      	POSIX::floor( $prefix_bytes[$m--] / 16 ) :
	$prefix_bytes[$m] % 16;
    }
    $origin .= sprintf( '%x.' x $digits . 'ip6.arpa.', @addr_digits );
  }
  return $origin;
}


####################################################################################
# is_address_included( $address )
####################################################################################
#
sub is_address_included($) {
  my $address = shift;

  # an undefined restrictions list treats every address as included
  if( !defined $address_restrictions_list ) {
    return 1;
  }
  foreach my $item ( @$address_restrictions_list ) {
    # decide and return on the first match
    if( is_ip_prefix_of( $item->[1], $address )) {
      if( DEBUG ) {
        my $prefix_str = sprint_prefix( $item->[1] );
        my $addr_str = sprint_address( $address );
        print 'DEBUG: ' . ( $item->[0] ? 'inc' : 'exc' ) . " $prefix_str matched $addr_str\n";
      }
      # match found, return inclusion/exclusion according to the current list item
      return $item->[0];
    }
  }
  if( DEBUG ) { print "DEBUG: implicit exc\n"; }
  # no match, implicit exclusion at the end of the restrictions list
  return 0;
}

####################################################################################
# is_string_included( $string, $re_list )
####################################################################################
#
sub is_string_included($$) {
  my $string = shift;
  my $re_list = shift;

  # an undefined restrictions list treats everything as included
  if( !defined $re_list ) {
    return 1;
  }
  foreach my $item ( @$re_list ) {
    # decide and return on the first match
    if( DEBUG ) {
      print "DEBUG: '$string' =~ '$item->[1]' ? ";
      print (( $string =~ $item->[1] ) ? "yes\n" : "no\n");
    }
    if( $string =~ $item->[1] ) {
      # match found, return inclusion/exclusion according to the current list item
      return $item->[0];
    }
  }
  # no match, implicit exclusion at the end of the restrictions list
  return 0;
}

sub convert_iface_name($) {
  my $name = lc( shift );

  my $it = $Options->{ 'interface-types' };
  # Replace interface types at the beginning of the interface name.
  foreach my $config_it ( keys %$it ) {
    my $dns_it = $it->{ $config_it };
    $name =~ s/^$config_it/$dns_it/i;
  }

  foreach my $sub ( @{ $Options->{ 'interface-subs' }}) {
    my $p = $sub->{ 'pattern' };
    my $s = '"' . $sub->{ 'substitution' } . '"';
    $name =~ s/$p/$s/ee;
  }

  # Replace special characters to '-' for the DNS label.
  $name =~ s/[:\.\/]/-/g;

  return $name;
}

sub verbose_message($$) {
  my $level = shift;
  my $msg = shift;

  if( $verbose_level >= $level ) {
    print '  'x($level-1) . $msg . "\n";
  }
}

sub omit_message($) {
  my $msg = shift;

  if( $omit_log ) {
    print '    omitted ===> ' . $msg . "\n";
  }
}

sub include_message($) {
  my $msg = shift;

  if( $include_log ) {
    print '    generated => ' . $msg . "\n";
  }
}

my $Arg_Config_File_Name = 'router2dns.conf';
my $Arg_Verbose = 1;
my $Arg_Help = 0;
my $Arg_Version = 0;

my $Config_Text;

####################################################################################
####################################################################################
#
# PROGRAM START
#
####################################################################################
####################################################################################

Getopt::Long::Configure( 'bundling' );
if( !GetOptions(
  'c|config-file-name=s' => \$Arg_Config_File_Name,
  'o|omit-log' => \$omit_log,
  'i|include-log' => \$include_log,
  'v|verbose:1' => \$verbose_level,
  'h|help|?' => \$Arg_Help,
  'V|version' => \$Arg_Version ))
{
  pod2usage( 2 );
}
if( $Arg_Help ) { pod2usage( 1 ); }

if( $Arg_Version ) {
  print MY_NAME . ' ' . MY_VERSION . "\n";
  exit( 0 );
}

#
# Read and parse the configuration file.
#
verbose_message( VERBOSE_PHASE, "Using script config file '$Arg_Config_File_Name'..." );
verbose_message( VERBOSE_PHASE_DETAIL, 'Reading config file...' );
$Config_Text = config_read( $Arg_Config_File_Name );

verbose_message( VERBOSE_PHASE_DETAIL, 'Parsing config file...' );
my $config_grammar = config_grammar_preproc( $config_grammar_in, $Arg_Config_File_Name );

my $parser = new Parse::RecDescent( $config_grammar );
if( !defined ( $Parsed_Cfg = $parser->ConfigFile( $Config_Text ))) {
  die( "\nError: Syntax error in config file $Arg_Config_File_Name.\n" .
	"  Please check the parser's first error message above.\n"  );
}

if( DEBUG ) {
  print "DEBUG: config dump:\n";
  print Dumper( $Parsed_Cfg );
}

#
# Process configuration parameters.
#
verbose_message( VERBOSE_PHASE_DETAIL, 'Processing parsed config...' );

#
#   options
#
if( exists( $Parsed_Cfg->{ 'options' } )) {
  my $p = $Parsed_Cfg->{ 'options' };

  $Options->{ 'config-base-dir' } = $p->{ 'config-base-dir' }{ 'val' } // '';
  $Options->{ 'output-dir' } = $p->{ 'output-dir' }{ 'val' } // '';
  $Options->{ 'rz-sort' } = 
    $p->{ 'reverse-zone-sort-by' }{ 'val' } // RZ_SORT_DEFAULT;
  $Options->{ 'register-unnumbered' } = 
    $p->{ 'register-unnumbered' }{ 'val' } // REGISTER_UNNUMBERED_DEFAULT;

  if( exists( $p->{ 'interface-type' } )) {
    foreach my $i ( @{ $p->{ 'interface-type' }} ) {
      foreach my $c ( @{ $i->{ 'config-name' }} ) {
        my $cl = lc( $c->{ 'val' });
        $Options->{ 'interface-types' }{ $cl } = $i->{ 'dns-name' }{ 'val' };
      }
    }
  }
  if( exists( $p->{ 'interface-substitution' } )) {
    foreach my $i ( @{ $p->{ 'interface-substitution' }} ) {
      if( !defined $i->{ 'pattern' }{ 'val' } ) {
	die( "\nError: Missing pattern in interface-substitution.\n" .
	  "  file $i->{ 'cfg_file' }, line $i->{ 'cfg_line' }\n" );
      }
      my $new_sub = { 
	'pattern' => $i->{ 'pattern' }{ 'val' },
	'substitution' => $i->{ 'substitution' }{ 'val' } // ''
      };
      push( @{ $Options->{ 'interface-subs' }}, $new_sub );
    }
  }
}

if( DEBUG ) {
  print Dumper( $Parsed_Cfg->{ 'options' } );
  print "DEBUG: options:\n";
  print Dumper( $Options );
}

#
#   forward-zones
#
if( exists( $Parsed_Cfg->{ 'forward-zones' } )) {
  foreach my $p ( @{ $Parsed_Cfg->{ 'forward-zones' }} ) {
    if( !exists( $p->{ 'name' } )) {
      die( "\nError: Parameter 'name' not specified for forward zone.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
    }
    my $zone = $p->{ 'name' }{ 'val' };

    # Check whether a forward zone for this domain name is unique (not defined already).
    foreach my $fwd ( @$forward_zones ) {
      if( $fwd->{ 'name' } eq $zone ) {
        die( "\nError: Multiple forward zones for domain '$zone'.\n" .
		"  file $fwd->{ 'cfg_file' }, line $fwd->{ 'cfg_line' }\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
      }
    }
    # Check whether the zone file is defined.
    if( !exists( $p->{ 'file' } )) {
      die( "\nError: Parameter 'file' not specified for forward zone '$zone'.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
    }
    # Check whether the zone file is unique.
    foreach my $z ( @$forward_zones ) {
      if( exists( $z->{ 'file' } )) {
        my $f = $z->{ 'file' };
	if( $f eq $p->{ 'file' }{ 'val' } ) {
	  die( "\nError: Multiple zones with output file '$f'.\n" .
		  "  file $z->{ 'cfg_file' }, line $z->{ 'cfg_line' }\n" .
		  "  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
	}
      }
    }

    my $new_forward = { 
      'name' => $p->{ 'name' }{ 'val' },
      'file' => $p->{ 'file' }{ 'val' },
      'cfg_file' => $p->{ 'cfg_file' },
      'cfg_line' => $p->{ 'cfg_line' },
      'entries' => [] };
    insert_forward_zone( $new_forward );

    #TODO: delegated forward zones
  }
}

if( exists( $Parsed_Cfg->{ 'devices' } )) {
  my $p = $Parsed_Cfg->{ 'devices' };
  if( exists( $p->{ 'ios-routers' } )) {
    foreach my $q ( @{ $p->{ 'ios-routers' }} ) {
      expand_list( $q, 'config' );
      foreach my $r ( @{ $q->{ 'config' }} ) {
	my $config_file_name = $r->{ 'val' };
	foreach my $d ( @$devices ) {
	  if( $d->{ 'config_file_name' } eq $config_file_name ) {
	    die( "\nError: Device config file '$config_file_name' specified twice.\n" .
		"  file $d->{ 'cfg_file' }, line $d->{ 'cfg_line' }\n" .
		"  file $r->{ 'cfg_file' }, line $r->{ 'cfg_line' }\n" );
	  } 
	}
	my $new_dev = { 
	  'config_file_name' => $config_file_name,
	  'cfg_file' => $r->{ 'cfg_file' },
	  'cfg_line' => $r->{ 'cfg_line' },
	  'type' => DEV_IOS_ROUTER,
	  'main-interface' => $q->{ 'main-interface' }{ 'val' } // MAINIF_DEFAULT,
	  'main-interface-rrs' => $q->{ 'main-interface-rrs' }{ 'val' } // MAINIFRR_DEFAULT,
	  'forward-zone-override' => $q->{ 'forward-zone-override' }{ 'val' } // FWDZ_OVERRIDE_DEFAULT };
	if( exists( $q->{ 'forward-zone' } )) {
	  $new_dev->{ 'forward-zone' } = $q->{ 'forward-zone' }{ 'val' };
	}
	push( @$devices, $new_dev );
      }
    }
  }
  if( exists( $p->{ 'junos-routers' } )) {
    foreach my $q ( @{ $p->{ 'junos-routers' }} ) {
      expand_list( $q, 'config' );
      # TODO
    }
  }
  if( exists( $p->{ 'ios-hosts' } )) {
    foreach my $q ( @{ $p->{ 'ios-hosts' }} ) {
      expand_list( $q, 'config' );
      foreach my $r ( @{ $q->{ 'config' }} ) {
	my $config_file_name = $r->{ 'val' };
	foreach my $d ( @$devices ) {
	  if( $d->{ 'config_file_name' } eq $config_file_name ) {
	    die( "\nError: Device config file '$config_file_name' specified twice.\n" .
		"  file $d->{ 'cfg_file' }, line $d->{ 'cfg_line' }\n" .
		"  file $r->{ 'cfg_file' }, line $r->{ 'cfg_line' }\n" );
	  }
	}
	my $new_dev =
	{ 'config_file_name' => $config_file_name,
	  'cfg_file' => $r->{ 'cfg_file' },
	  'cfg_line' => $r->{ 'cfg_line' },
	  'type' => DEV_IOS_HOST,
	  'forward-zone-override' => $q->{ 'forward-zone-override' }{ 'val' } // FWDZ_OVERRIDE_DEFAULT };
	if( exists( $q->{ 'forward-zone' } )) {
	  $new_dev->{ 'forward-zone' } = $q->{ 'forward-zone' }{ 'val' };
	}
	push( @$devices, $new_dev );
      }
    }
  }
}

if( exists( $Parsed_Cfg->{ 'restrictions' } )) {
  my $p = $Parsed_Cfg->{ 'restrictions' };

  if( exists( $p->{ 'address-list' } )) {
    if( exists( $p->{ 'address-list' }{ 'entries' } )) {
      foreach my $q ( @{ $p->{ 'address-list' }{ 'entries' }} ) {
	my $prefix_str = $q->{ 'val' };
        # Check prefix string syntax. Convert it to internal packed format.
	my $prefix_pack = pack_prefix( $prefix_str );
	if( !defined $prefix_pack ) {
	  die( "\nError: Invalid prefix '$prefix_str'.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
	}
        my $new_entry = [ ( $q->{ 'keyword' } =~ /include/i ) ? 1 : 0, $prefix_pack ];
	push( @$address_restrictions_list, $new_entry );
      }
    } else {
      $address_restrictions_list = [];
    }
  }
  if( exists( $p->{ 'vrf-list' } )) {
    if( exists( $p->{ 'vrf-list' }{ 'entries' } )) {
      foreach my $q ( @{ $p->{ 'vrf-list' }{ 'entries' }} ) {
        my $new_entry = [ ( $q->{ 'keyword' } =~ /include/i ) ? 1 : 0, qr/$q->{ 'val' }/ ];
	push( @$vrf_restrictions_list, $new_entry );
      }
    } else {
      $vrf_restrictions_list = [];
    }
  }
  if( exists( $p->{ 'interface-list' } )) {
    if( exists( $p->{ 'interface-list' }{ 'entries' } )) {
      foreach my $q ( @{ $p->{ 'interface-list' }{ 'entries' }} ) {
        my $new_entry = [ ( $q->{ 'keyword' } =~ /include/i ) ? 1 : 0, qr/$q->{ 'val' }/ ];
	push( @$int_restrictions_list, $new_entry );
      }
    } else {
      $int_restrictions_list = [];
    }
  }
}

if( DEBUG ) {
  print "DEBUG: forward-zones:\n";
  print Dumper( $forward_zones );
  print "DEBUG: devices:\n";
  print Dumper( $devices );
  print "DEBUG: address restrictions:\n";
  print Dumper( $address_restrictions_list );
  print "DEBUG: vfr restrictions:\n";
  print Dumper( $vrf_restrictions_list );
  print "DEBUG: interface restrictions:\n";
  print Dumper( $int_restrictions_list );
}

#
#   reverse-zones
#
if( exists( $Parsed_Cfg->{ 'reverse-zones' } )) {
  foreach my $p ( @{ $Parsed_Cfg->{ 'reverse-zones' }} ) {


    # Check the new reverse zone.
    #
    # Check whether the reverse zone's prefix is defined.
    if( !exists( $p->{ 'prefix' } )) {
      die( "\nError: Parameter 'prefix' not specified for reverse zone.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
    }
    my $prefix_str = $p->{ 'prefix' }{ 'val' };
    # Check prefix string syntax. Convert it to internal packed format.
    my $prefix_pack = pack_prefix( $prefix_str );
    if( !defined $prefix_pack ) {
      die( "\nError: Invalid prefix '$prefix_str'.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
    }
    # Use canonical form of prefix string.
    $prefix_str = sprint_prefix( $prefix_pack );

    # Check the prefix length.
    my ( $prefix_len, @addr_bytes ) = unpack( 'C C/C', $prefix_pack );
    if( scalar @addr_bytes == 4 ) {
      # IPv4
      if(( $prefix_len < 24 ) && ( $prefix_len % 8 )) {
        die( "\nError: Reverse zone prefix '$prefix_str' is invalid.\n" .
		"Prefix length must be 0, 8, 16, or >= 24.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
      }	
    }
    elsif ( scalar @addr_bytes == 16 ) {
      # IPv6
      if( $prefix_len % 4 ) {
        die( "\nError: Reverse zone prefix '$prefix_str' is invalid.\n" .
		"Prefix length must be multiple of 4.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
      }
    }
    # Check whether a reverse zone for this prefix is unique (not defined already).
    foreach my $rev ( @$reverse_zones ) {
      if( is_prefix_eq( $rev->{ 'prefix' }, $prefix_pack )) {
        die( "\nError: Multiple reverse zones for prefix '$prefix_str'.\n" .
		"  file $rev->{ 'cfg_file' }, line $rev->{ 'cfg_line' }\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
      }
    }
    # Check whether the zone file is defined.
    if( !exists( $p->{ 'file' } )) {
      die( "\nError: Parameter 'file' not specified for reverse zone '$prefix_str'.\n" .
		"  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
    }
    # Check whether the zone file is unique.
    foreach my $z ( @$reverse_zones, @$forward_zones ) {
      if( exists( $z->{ 'file' } )) {
        my $f = $z->{ 'file' };
	if( $f eq $p->{ 'file' }{ 'val' } ) {
	  die( "\nError: Multiple zones with output file '$f'.\n" .
		  "  file $z->{ 'cfg_file' }, line $z->{ 'cfg_line' }\n" .
		  "  file $p->{ 'cfg_file' }, line $p->{ 'cfg_line' }\n" );
	}
      }
    }



    # Build reverse zone record and insert it into the list.
    #
    my $new_rev = { 'file' => $p->{ 'file' }{ 'val' },
	  'cfg_file' => $p->{ 'cfg_file' },
	  'cfg_line' => $p->{ 'cfg_line' },
	  'prefix' => $prefix_pack,
	  'prefix_str' => $prefix_str,
	  'entries' => [] };
    insert_reverse_zone( $new_rev );

    # Process delegated parts of the reverse zone.
    if( exists( $p->{ 'delegated' } )) {
      my $q = $p->{ 'delegated' };

      # Process 'name' and 'name-list-file' entries.

      # Expand 'name-list-file' config entries into 'name' entries.
      expand_list( $q, 'name' );
      foreach my $r ( @{ $q->{ 'name' }} ) {
	my $deleg_name = $r->{ 'val' };
	# Check name syntax. Convert it to prefix.
	my $deleg_prefix_pack = prefix_of_reverse_name( $prefix_pack, $deleg_name );
	if( !defined $deleg_prefix_pack ) {
	  die( "\nError: Invalid delegation name '$deleg_name' in reverse zone '$prefix_str'.\n" .
	      "  file $r->{ 'cfg_file' }, line $r->{ 'cfg_line' }\n" );
	}
	# Use canonical form of prefix string.
	my $deleg_prefix_str = sprint_prefix( $deleg_prefix_pack );

	# Check whether this prefix is unique (not defined as a reverse zone's
	# prefix or as a delegated prefix).
	foreach my $rev ( @$reverse_zones ) {
	  if( is_prefix_eq( $rev->{ 'prefix' }, $deleg_prefix_pack )) {
	    die( "\nError: Reverse zone '$deleg_prefix_str' already defined.\n" .
		"  file $rev->{ 'cfg_file' }, line $rev->{ 'cfg_line' }\n" .
		"  file $r->{ 'cfg_file' }, line $r->{ 'cfg_line' }\n" );
	  }
	}

	# Build delegated prefix record.
	#
	# 'file' is not defined for delegated zones.
	my $new_deleg = {
	  'cfg_file' => $r->{ 'cfg_file' },
	  'cfg_line' => $r->{ 'cfg_line' },
	  'prefix' => $deleg_prefix_pack,
	  'prefix_str' => $deleg_prefix_str };
	insert_reverse_zone( $new_deleg );
      }

      # Process 'prefix' and 'prefix-list-file' entries.

      # Expand 'prefix-list-file' config entries into 'prefix' entries.
      expand_list( $q, 'prefix' );
      foreach my $r ( @{ $q->{ 'prefix' }} ) {
	my $deleg_prefix_str = $r->{ 'val' };
	# Check prefix string syntax. Convert it to internal packed format.
	my $deleg_prefix_pack = pack_prefix( $deleg_prefix_str );
	if( !defined $deleg_prefix_pack ) {
	  die( "\nError: Invalid prefix '$deleg_prefix_str'.\n" .
	      "  file $r->{ 'cfg_file' }, line $r->{ 'cfg_line' }\n" );
	}
	# Use canonical form of prefix string.
	$deleg_prefix_str = sprint_prefix( $deleg_prefix_pack );
	# Check whether the delegated prefix is inside the zone's prefix.
	if( !is_ip_prefix_of( $prefix_pack, $deleg_prefix_pack )) {
	  die( "\nError: Prefix '$deleg_prefix_str' is outside '$prefix_str'.\n" .
	      "  file $r->{ 'cfg_file' }, line $r->{ 'cfg_line' }\n" );
	}

	# Check whether this prefix is unique (not defined as a reverse zone's
	# prefix or as a delegated prefix).
	foreach my $rev ( @$reverse_zones ) {
	  if( is_prefix_eq( $rev->{ 'prefix' }, $deleg_prefix_pack )) {
	    die( "\nError: Reverse zone '$deleg_prefix_str' already defined.\n" .
		"  file $rev->{ 'cfg_file' }, line $rev->{ 'cfg_line' }\n" .
		"  file $r->{ 'cfg_file' }, line $r->{ 'cfg_line' }\n" );
	  }
	}

	# Build delegated prefix record.
	#
	# 'file' is not defined for delegated zones.
	my $new_deleg = {
	  'cfg_file' => $r->{ 'cfg_file' },
	  'cfg_line' => $r->{ 'cfg_line' },
	  'prefix' => $deleg_prefix_pack,
	  'prefix_str' => $deleg_prefix_str };
	insert_reverse_zone( $new_deleg );
      }
    }
  }
}

if( DEBUG ) {
  print "DEBUG: reverse-zones:\n";
  print Dumper( $reverse_zones );
}


####################################################################################
#
# process router configuration files
#
####################################################################################
verbose_message( VERBOSE_PHASE, 'Processing router config files...' );
foreach my $device ( @$devices ) {
  my $confg_fn = $device->{ 'config_file_name' };
  my $confg_fh = new IO::File;
  my $line_num = 1;
  my $line;

  my $hostname;
  my $domainname;
  my $fqdn;

  my $addrs = [];

  my $fwd_entries = undef;
  my $fwd_deleg = 0;

  $confg_fn = ( $Options->{ 'config-base-dir' } // '' ) . $confg_fn;

  verbose_message( VERBOSE_PHASE_DETAIL, "Processing '$confg_fn'..." );

  $confg_fh->open( "< $confg_fn" ) or
    die( "\nError: Cannot open device config file '$confg_fn'.\n" .
	"  file '$device->{ 'cfg_file' }', line $device->{ 'cfg_line' }\n" );

  given( $device->{ 'type' } ) {
    when( [ DEV_IOS_ROUTER, DEV_IOS_HOST ] ) {
      while( defined( $line = $confg_fh->getline )) {
	chomp $line;
	given( $line ) {
	  when( /^hostname\s+([^\s]+)\s*$/ ) {
	    if( !defined $hostname ) {
	      $hostname = $1;
	      verbose_message( VERBOSE_INTERFACE, "Found hostname '$hostname'." );
	    }
	  }
	  when( /^(ip )?domain[ -]name (.+)$/ ) {
	    if( !defined $domainname ) {
	      $domainname = $2;
	      verbose_message( VERBOSE_INTERFACE, "Found domain name '$domainname'." );
	    }
	  }
	}
      }
    }
  }
  if( !defined $hostname ) {
    die( "\nError: Missing hostname in device config file '$confg_fn'.\n" .
	"  file '$device->{ 'cfg_file' }', line $device->{ 'cfg_line' }\n" );
  }
  if(( defined $device->{ 'forward-zone' } ) and 
  	(( !defined $domainname ) or $device->{ 'forward-zone-override' })) {
    $domainname = $device->{ 'forward-zone' };
    verbose_message( VERBOSE_INTERFACE, "Using domain name '$domainname' from router2dns config." );
  }
  $fqdn = $hostname;
  if( defined( $domainname )) {
    $fqdn .= '.' . $domainname;
  }
  verbose_message( VERBOSE_DEVICE, "Device's FQDN is '$fqdn'." );

  foreach my $fz ( @$forward_zones ) {
    if( is_domain_postfix_of( $fz->{ 'name' }, $fqdn )) {
      verbose_message( VERBOSE_DEVICE, "Using forward zone '$fz->{ 'name' }'." );
      if( !defined $fz->{ 'file' } ) {
	$fwd_deleg = 1;
      } else {
	$fwd_entries = $fz->{ 'entries' };
	push( @$fwd_entries, { 'type' => ENTRY_START, 'hostname' => $fqdn } );
	last;
      }
    }
  }
  if( !defined $fwd_entries ) {
    omit_message( "'$fqdn' A/AAAA/CNAME RRs (no forward zone)" );
  } elsif( $fwd_deleg ) {
    omit_message( "'$fqdn' A/AAAA/CNAME RRs (delegated)" );
  }

  if( $Options->{ 'rz-sort' } == RZ_SORT_BY_DEVICE ) {
    foreach my $rz ( @$reverse_zones ) {
      if( defined $rz->{ 'file' } ) {
	my $rev_entries = $rz->{ 'entries' };
	push( @$rev_entries, { 'type' => ENTRY_START, 'hostname' => $fqdn } );
      }
    }
  }

  $confg_fh->seek( 0, SEEK_SET ) or
    die( "\nError: Cannot seek device config file '$confg_fn' to 0.\n" .
	"  file '$device->{ 'cfg_file' }', line $device->{ 'cfg_line' }\n" );
  $line_num = 1;

  # Collect IP addresses from the device's config file.
  given( $device->{ 'type' } ) {
    when( [ DEV_IOS_ROUTER, DEV_IOS_HOST ] ) {

      my @ipv4_addrs_pri;
      my @ipv4_addrs_sec;
      my @ipv6_addrs_pri;
      my @ipv6_addrs_sec;
      my $ipv4_unnumbered;
      my $ipv6_unnumbered;
      my $if_up = 1;
      my $vrf_name = '';

      my $iface_name;	# only defined while we're inside an interface's config

      COLLECTADDRS: while( defined( $line = $confg_fh->getline )) {
	chomp $line;

	# A given interface's configuration ends with the first unindented line.
	if( $line !~ /^\s/ ) {
	  # This is an unindented line.
	  if( defined $iface_name ) {
	    # We were inside an interface's config on the previus line. We just finished
	    # reading the interface's config.
	    if( !$if_up ) {
	      verbose_message( VERBOSE_IP, 'Interface is shut down.' );
	    }
	    else {
	      my $i = {
		'name' => $iface_name, 
		'vrf' => $vrf_name };
	      if( defined $ipv4_unnumbered ) {
	        $i->{ 'ipv4_unnumbered' } = $ipv4_unnumbered;
	      }
	      if( @ipv4_addrs_pri + @ipv4_addrs_sec ) {
		$i->{ 'ipv4_addrs' } = [( @ipv4_addrs_pri, @ipv4_addrs_sec )];
	      }
	      if( defined $ipv6_unnumbered ) {
	        $i->{ 'ipv6_unnumbered' } = $ipv6_unnumbered;
	      }
	      if( @ipv6_addrs_pri + @ipv6_addrs_sec ) {
		$i->{ 'ipv6_addrs' } = [( @ipv6_addrs_pri, @ipv6_addrs_sec )];
	      }
	      push( @$addrs, $i );
	    }
	    # We're now outside the interface's config.
	    # Assume the next interface to be up (until we find 'shutdown' in its config).
	    $if_up = 1;
	    # Assume the next interface is in the global VRF.
	    $vrf_name = '';
	    undef $iface_name;
	    undef @ipv4_addrs_pri;
	    undef @ipv4_addrs_sec;
	    undef @ipv6_addrs_pri;
	    undef @ipv6_addrs_sec;
	    undef $ipv4_unnumbered;
	    undef $ipv6_unnumbered;
	  }
	}

	my $iface_name_re = qr/([^\s]+[[:digit:]])/;

	if( !defined $iface_name ) {
	  if( $line =~ /^interface\s+${iface_name_re}(\s.*)?$/ ) {
	    verbose_message( VERBOSE_INTERFACE, "Processing interface '$1'..." );
	    my $in = convert_iface_name( $1 );
	    if( is_string_included( "$1", $int_restrictions_list )) {
	      $iface_name = $in;
	    } else {
	      omit_message( "'$hostname/$in' RRs (interface name excluded)" );
	    }
	  }
	}
	else {
	  # We are inside an interface's configuration.
	  given( $line ) {
	    when( /^\s+shutdown$/ ) {
	      $if_up = 0;
	    }
	    when( /^\s+ip(v4)?\s+unnumbered\s+${iface_name_re}(\s.*)?$/i ) {
	      verbose_message( VERBOSE_IP, "IPv4 unnumbered '$2'." );
	      $ipv4_unnumbered = convert_iface_name( $2 );
	    }
	    when( /^\s+ipv6\s+unnumbered\s+${iface_name_re}(\s.*)?$/i ) {
	      verbose_message( VERBOSE_IP, "IPv6 unnumbered '$1'." );
	      $ipv6_unnumbered = convert_iface_name( $1 );
	    }
	    when( /^\s+ip(v4)?\s+address\s+([[:digit:].]+)\s+[[:digit:].]+\s+secondary(\s.*)?$/i ) {
	      if( is_v4_addr_str( $2 )) {
	        my $p = pack_prefix( $2 );
		my $s = sprint_address( $p );
		verbose_message( VERBOSE_IP, "Found secondary IPv4 address '$s'." );
		push( @ipv4_addrs_sec, $p );
	      }
	    }
	    when( /^\s+ip(v4)?\s+address\s+([[:digit:].]+)\s+[[:digit:].]+(\s.*)?$/i ) {
	      if( is_v4_addr_str( $2 )) {
	        my $p = pack_prefix( $2 );
		my $s = sprint_address( $p );
		verbose_message( VERBOSE_IP, "Found primary IPv4 address '$s'." );
		push( @ipv4_addrs_pri, $p );
	      }
	    }
	    when( /^\s+ipv6\s+address\s+([[:xdigit:]:]+)\/[[:digit:].]+\s+eui-64(\s.*)?$/i ) {
	      #TODO: SNMP?
	      break;
	    }
	    when( /^\s+ipv6\s+address\s+([[:xdigit:]:]+)\/[[:digit:].]+\s+link-local(\s.*)?$/i ) {
	      break;
	    }
	    when( /^\s+ipv6\s+address\s+([[:xdigit:]:]+)\/[[:digit:].]+\s+anycast(\s.*)?$/i ) {
	      if( is_v6_addr_str( $1 )) {
	        my $p = pack_prefix( $1 );
		my $s = sprint_address( $p );
		verbose_message( VERBOSE_IP, "Found anycast IPv6 address '$s'." );
		push( @ipv6_addrs_sec, $p );
	      }
	    }
	    when( /^\s+ipv6\s+address\s+([[:xdigit:]:]+)\/[[:digit:]]+(\s.*)?$/i ) {
	      if( is_v6_addr_str( $1 )) {
	        my $p = pack_prefix( $1 );
		my $s = sprint_address( $p );
		verbose_message( VERBOSE_IP, "Found IPv6 address '$s'." );
		push( @ipv6_addrs_pri, $p );
	      }
	    }
	    when( /^\s+(ip\s+)?vrf\s+(forwarding\s+)?([^\s]+)(\s.*)?$/i ) {
	      $vrf_name = $3;
	      verbose_message( VERBOSE_IP, "Interface belongs to the '$3' VRF." );
	    }
	  }
	}
	$line_num++;
      }
    }
  }

  if( DEBUG ) {
    print "DEBUG: addrs:\n";
    print Dumper( $addrs );
  }

  # Record necessary DNS entries for every interface.
  my $host_done = 0;
  foreach my $i ( @$addrs ) {
    my $iface_name = $i->{ 'name' };
    my $ipv4_addrs = $i->{ 'ipv4_addrs' };
    my $ipv6_addrs = $i->{ 'ipv6_addrs' };
    my $vrf_name = $i->{ 'vrf' };

    if( $host_done && ( $device->{ 'type' } == DEV_IOS_HOST )) {
      omit_message( "'$hostname/$iface_name' RRs (not first interface of host device)" );
      next;
    }
    if( !is_string_included( $vrf_name, $vrf_restrictions_list )) {
      omit_message( "'$hostname/$iface_name' RRs (VRF '$vrf_name' excluded)" );
      next;
    }

    my $label = $iface_name;
    if( $device->{ 'type' } == DEV_IOS_ROUTER ) {
      if( $iface_name eq $device->{ 'main-interface' } ) {
	given( $device->{ 'main-interface-rrs' } ) {
	  when( MAINIF_HOSTNAME ) {
	    undef $label;
	  }
	  when( MAINIF_CNAME ) {
	    if( defined $fwd_entries ) {
	      push( @$fwd_entries, {
		  'type' => ENTRY_CNAME,
		  'label' => '@',
		  'cname' => $iface_name,
		  'deleg' => $fwd_deleg } );
	      if( !$fwd_deleg ) {
		include_message( "'$hostname' -> '$iface_name' CNAME RR" );
	      }
	    }
	  }
	}
      }
    } else {
      undef $label;
    }
    foreach my $addr ( @$ipv4_addrs, @$ipv6_addrs ) {
      my $s = sprint_address( $addr );
      if( !is_address_included( $addr )) {
	next;
      }

      my $rev_deleg = 0;
      my $rev_entries;
      foreach my $rz ( @$reverse_zones ) {
	if( !is_ip_prefix_of( $rz->{ 'prefix' }, $addr )) {
	  next;
	}
	if( !defined $rz->{ 'file' } ) {
	  $rev_deleg = 1;
	} else {
	  $rev_entries = $rz->{ 'entries' };
	  push( @$rev_entries, {
	      'type' => ENTRY_PTR,
	      'addr' => $addr,
	      'name' => ( defined $label ? $label . '.' : '' ) . "$fqdn.",
	      'deleg' => $rev_deleg } );
	  if( $rev_deleg ) {
	    omit_message( "'$hostname/$iface_name/$s' PTR RR (delegated)" );
	  } else {
	    include_message( "'$hostname/$iface_name/$s' PTR RR" );
	  }
	  last;
	}
      }
      if( !defined $rev_entries ) {
	omit_message( "'$hostname/$iface_name/$s' PTR RR (no reverse zone)" );
      }
    }

    if( defined $i->{ 'ipv4_unnumbered' } ) {
      if( $Options->{ 'register-unnumbered' }) {
	foreach my $s ( @$addrs ) {
	  if( $s->{ 'name' } eq $i->{ 'ipv4_unnumbered' } ) {
	    my $s4 = $s->{ 'ipv4_addrs' };
	    unshift( @$ipv4_addrs, @$s4 );
	    last;
	  }
	}
      } else {
	omit_message( "'$hostname/$iface_name' (not registering unnumbered interfaces)" );
      }
    }
    if( defined $i->{ 'ipv6_unnumbered' } ) {
      if( $Options->{ 'register-unnumbered' }) {
	foreach my $s ( @$addrs ) {
	  if( $s->{ 'name' } eq $i->{ 'ipv6_unnumbered' } ) {
	    my $s6 = $s->{ 'ipv6_addrs' };
	    unshift( @$ipv6_addrs, @$s6 );
	    last;
	  }
	}
      } else {
	omit_message( "'$hostname/$iface_name' (not registering unnumbered interfaces)" );
      }
    }
    if( !defined $ipv4_addrs && !defined $ipv6_addrs ) {
      next;
    }
    my $ipv4_fwd_done = 0;
    my $ipv6_fwd_done = 0;
    foreach my $addr ( @$ipv4_addrs, @$ipv6_addrs ) {
      my $s = sprint_address( $addr );
      if( !is_address_included( $addr )) {
	omit_message( "'$hostname/$iface_name/$s' RRs (address excluded)" );
	next;
      }
      $host_done = 1;
      if( defined $fwd_entries ) {
	my $type;
	given( get_address_ver( $addr )) {
	  when( 4 ) {
	    if( $ipv4_fwd_done ) {
	      omit_message( "'$hostname/$iface_name/$s' (already got A RR)" );
	    } else {
	      $type = ENTRY_A;
	      $ipv4_fwd_done = 1;
	    }
	  }
	  when( 6 ) {
	    if( $ipv6_fwd_done ) {
	      omit_message( "'$hostname/$iface_name/$s' (already got AAAA RR)" );
	    } else {
	      $type = ENTRY_AAAA;
	      $ipv6_fwd_done = 1;
	    }
	  }
	  default {
	    if( DEBUG ) {
	      print "DEBUG: Error: Unknown IP address version.\n";
	    }
	  }
	}
	if( defined $type ) {
	  push( @$fwd_entries, {
	      'type' => $type,
	      'label' => $label // '@',
	      'addr' => $addr,
	      'deleg' => $fwd_deleg } );
	  if( !$fwd_deleg ) {
	    my $t;
	    given( $type ) {
	      when( ENTRY_A ) { $t = 'A' }
	      when( ENTRY_AAAA ) { $t = 'AAAA' }
	    }
	    include_message( "'$hostname/$iface_name/$s' $t RR" );
	  }
	}
      }
    }
  }
  undef $confg_fh;
}

if( DEBUG ) {
  print "DEBUG: forward-zone:\n";
  print Dumper( $forward_zones );
  print "DEBUG: reverse-zones:\n";
  print Dumper( $reverse_zones );
}

verbose_message( VERBOSE_PHASE, 'Writing zone files...' );

foreach my $fz ( @$forward_zones ) {
  if( !defined $fz->{ 'file' } ) { next; }

  my $fh = new IO::File;
  my $file_name = $fz->{ 'file' };

  $file_name = ( $Options->{ 'output-dir' } // '' ) . $file_name;

  verbose_message( VERBOSE_ZONE,
  	"Writing forward zone '$fz->{ 'name' }' to '$file_name'..." );

  $fh->open( "> $file_name" ) or die( "\nError: Cannot open zone file '$file_name'.\n" );

  print $fh "\n\n; --START-- " . generated_message();

  my $entries = $fz->{ 'entries' };
  my $h;
  foreach my $e ( @$entries ) {
    my $a;
    given( $e->{ 'type' } ) {
      when( ENTRY_START ) {
	$h = $e->{ 'hostname' };
        verbose_message( VERBOSE_DEVICE, "Writing records for '$h'..." );
	print $fh "\n\n\$ORIGIN $e->{ 'hostname' }.\n\n";
      }
      when( [ ENTRY_A, ENTRY_AAAA ] ) {
	$a = sprint_address( $e->{ 'addr' } );
        continue;
      }
      when( ENTRY_CNAME ) {
	$a = $e->{ 'cname' };
	continue;
      }
      when( [ ENTRY_A, ENTRY_AAAA, ENTRY_CNAME ] ) {
        my $r = (RR_TYPE)[$_];
	my $l = $e->{ 'label' };
	if( $e->{ 'deleg' } ) {
	  print $fh ";delegated:\n";
	  $l = ";$l";
	} else {
	  my $d = '';
	  if( $l ne '@' ) {
	    $d = $l . '.';
	  }
	  verbose_message( VERBOSE_RR, "$d$h $r $a" );
	}
	my $len = length( $l );
	$l .= "\t" x ( POSIX::floor(( 23 - $len ) / 8 ));
	print $fh "$l\tIN\t$r\t$a\n";
      }
    }
  }

  print $fh "\n\n; --STOP-- " . generated_message() . "\n";

  undef $fh;
}

foreach my $rz ( @$reverse_zones ) {
  # Skip delegated zones, no entries recorded there.
  if( !defined $rz->{ 'file' } ) { next; }

  my $entries = $rz->{ 'entries' };

  if( $Options->{ 'rz-sort' } == RZ_SORT_BY_ADDRESS ) {
    verbose_message( VERBOSE_ZONE, 
	"Sorting reverse zone '$rz->{ 'prefix_str' }' entries by address..." );
    $entries = [ sort rz_entry_cmp @$entries ];
  }

  my $fh = new IO::File;
  my $file_name = $rz->{ 'file' };

  $file_name = ( $Options->{ 'output-dir' } // '' ) . $file_name;

  verbose_message( VERBOSE_ZONE, 
  	"Writing reverse zone '$rz->{ 'prefix_str' }' to '$file_name'..." );

  $fh->open( "> $file_name" ) or die( "\nError: Cannot open zone file '$file_name'.\n" );

  print $fh "\n\n; --START-- " . generated_message();

  print $fh "\n\$ORIGIN " . origin_of_reverse_zone( $rz->{ 'prefix' }) . "\n\n";

  for( my $n = 0; $n < scalar @$entries; $n++ ) {
    my $e = $entries->[$n];
    given( $e->{ 'type' } ) {
      when( ENTRY_START ) {
        # Print header comment only if there are non-comment entries afterwards.
	if(( $n+1 < scalar @$entries ) && ( $entries->[$n+1]->{ 'type' } != ENTRY_START )) {
          verbose_message( VERBOSE_DEVICE, "Writing records for '$e->{ 'hostname' }'..." );
	  print $fh "\n\n; $e->{ 'hostname' }\n\n";
	} else {
          #verbose_message( VERBOSE_DEVICE, "No records for '$e->{ 'hostname' }'." );
	}
      }
      when( ENTRY_PTR ) {
        my $label = label_of_reverse_record( $rz->{ 'prefix' }, $e->{ 'addr' } );
	if( $e->{ 'deleg' } ) {
	  print $fh ";delegated:\n";
	  $label = ";$label";
	} else {
	  my $s = sprint_address( $e->{ 'addr' } );
	  verbose_message( VERBOSE_RR, "$s PTR $e->{ 'name' }" );
	}
	my $len = length( $label );
	if( $len <= 15 ) {
	  $label .= "\t\t";
	  if( $len < 8 ) {
	    $label .= "\t";
	  }
	} else {
	  $label .= "\t" x ( POSIX::floor(( 63 - $len ) / 8 ));
	}
	print $fh $label . "IN\tPTR\t" . $e->{ 'name' } . "\n";

      }
    }
  }
  print $fh "\n\n; --STOP-- " . generated_message() . "\n";

  $fh->close;
}

verbose_message( VERBOSE_PHASE, 'Success.' );
exit 0;

__END__

=head1 NAME

router2dns - create router interface DNS entries from router configurations

=head1 SYNOPSIS

router2dns.pl -V

router2dns.pl -h

router2dns.pl -?

router2dns.pl [-vvvvv | -v level] [-c filename]

=head1 OPTIONS

=over

=item B<-V> or B<--version>

Display router2dns.pl version and exit.

=item B<-?> or B<-h> or B<--help>

Display short help and exit.

=item B<-v> level or B<--verbose> level

Produce verbose output. Level is 1 by default, acceptable values are 
0 (silent) to 4 (most verbose).

=item B<-c> filename or --config-file-name filename

Use filename as the router2dns configuration file. Default is
router2dns.conf

=item B<-i> or B<--include-log>

Log generated DNS resource records.

=item B<-o> filename or B<--omit-log>

Log omitted entities.

=back

=cut
