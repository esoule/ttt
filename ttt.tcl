#!/usr/local/bin/bltwish -f

# 
#   ttt variables 
#
### set interface to use
#set ttt_interface "le0"
### set colors to use
#set ttt_colors "red green blue cyan magenta yellow"
### set interval in milli second
#set ttt_interval 2000  
### set no host name translation
#set ttt_nohostname 1
### set udp port number
#set ttt_portno	6544
### set address
#set ttt_viewaddr 224.6.6.6

#
# set blt library path
#
if { [file exists /usr/local/blt/lib/blt2.1] } {
    global blt_library
    set blt_library /usr/local/blt/lib/blt2.1
}
if { [file exists /usr/local/lib/blt2.4] } {
    global blt_library
    set blt_library /usr/local/lib/blt2.4
}
global auto_path
lappend auto_path $blt_library

# Try to import the blt namespace into the global scope.  If it
# fails, we'll assume BLT was loaded into the global scope.

if { $tcl_version >= 8.0 } {
    catch {namespace import blt::*} 
} else {
    catch { import add blt }
}

#	Add a binding for convenience to let you exit with pressing 
#	the "quit" button.

wm protocol . WM_DELETE_WINDOW { DoExit 0 }
bind all <Control-KeyPress-c> { DoExit 0 } 
bind all <KeyPress-q> { DoExit 0 }
focus .

proc DoExit { code } {
    exit $code
}

if { [info commands "namespace"] == "namespace" } {
    if { $tcl_version >= 8.0 } {
	catch {namespace import -force blt::tile::*} 
    } else {
	catch { import add blt::tile }
    }
} else {
    foreach cmd { button checkbutton radiobutton frame label 
	scrollbar toplevel menubutton listbox } {
	if { [info command tile${cmd}] == "tile${cmd}" } {
	    rename ${cmd} ""
	    rename tile${cmd} ${cmd}
	}
    }
}

#image create photo bgTexture -file ./bitmaps/rain.gif

#option add *Graph.Tile			bgTexture
#option add *Label.Tile			bgTexture
#option add *Frame.Tile			bgTexture
#option add *Htext.Tile			bgTexture
option add *TileOffset			0
option add *HighlightThickness		0
option add *takeFocus			yes

set visual [winfo screenvisual .] 
if { $visual != "staticgray" } {
    option add *print.background yellow
    option add *quit.background red
}

proc FormatLabel { w value } {
    puts stderr "tick is $value"
    return $value
}

frame .f
set remote {}
set graph .graph
set graph2 .graph2
set num 0

graph $graph -title "Protocol Breakdown" -bufferelements false -plotbackground gray90
$graph xaxis configure \
	-loose 1 \
	-title "Time (sec)" 
$graph yaxis configure \
	-title "Traffic (Mbps)" 
$graph legend configure \
	-activerelief sunken \
	-background ""

graph $graph2 -title "Host Breakdown" -bufferelements false -plotbackground gray90
$graph2 xaxis configure \
	-loose 1 \
	-title "Time (sec)" 
$graph2 yaxis configure \
	-title "Traffic (Mbps)" 
$graph2 legend configure \
	-activerelief sunken \
	-background ""

htext .footer -text {\
Hit the %%
button $htext(widget).quit -text quit -command { 
    send [winfo name .] {ttt cleanup}
    catch "send GraphConfig after 1 exit" 
    exit
} 
$htext(widget) append $htext(widget).quit 
%% button when you've seen enough.
To create postscript files "/tmp/{proto_*, host_*}.ps", 
press the %%
    button $htext(widget).print -text print -command {
        .graph postscript output "/tmp/proto_${num}.ps" \
	     -maxpect 1 -landscape 0 -center 1 -decorations 0
        .graph2 postscript output "/tmp/host_${num}.ps" \
	     -maxpect 1 -landscape 0 -center 1 -decorations 0
	incr num
    } 
    $htext(widget) append $htext(widget).print
%% button.}

# vectors X:time  P:protocols  H:hosts
if { $blt_version == 2.1 } {
    vector X 
    vector P0 P1 P2 P3 P4 P5 
    vector H0 H1 H2 H3 H4 H5
} else {
    # blt_version >= 2.3
    vector create X -variable ""
    for { set i 0 } { $i <= 5 } {incr i } {
	vector create P${i} -variable ""
	vector create H${i} -variable ""
    }
}

$graph element create p0 -xdata X -ydata P0 \
    -symbol none -label "" -color red
$graph element create p1 -xdata X -ydata P1 \
    -symbol none -label "" -color green -dashes { 8 4 }
$graph element create p2 -xdata X -ydata P2 \
    -symbol none -label "" -color blue -dashes { 5 4 }
$graph element create p3 -xdata X -ydata P3 \
    -symbol none -label "" -color orange -dashes { 3 5 }
$graph element create p4 -xdata X -ydata P4 \
    -symbol none -label "" -color purple -dashes { 3 6 }
$graph element create p5 -xdata X -ydata P5 \
    -symbol none -label "" -color yellow -dashes { 2 9 }

$graph2 element create h0 -xdata X -ydata H0 \
    -symbol none -label "" -color red
$graph2 element create h1 -xdata X -ydata H1 \
    -symbol none -label "" -color green -dashes { 8 4 }
$graph2 element create h2 -xdata X -ydata H2 \
    -symbol none -label "" -color blue -dashes { 5 4 }
$graph2 element create h3 -xdata X -ydata H3 \
    -symbol none -label "" -color orange -dashes { 3 5 }
$graph2 element create h4 -xdata X -ydata H4 \
    -symbol none -label "" -color purple -dashes { 3 6 }
$graph2 element create h5 -xdata X -ydata H5 \
    -symbol none -label "" -color yellow -dashes { 2 8 }


# capture stat:
set ttt_packets "0"
set ttt_drops "0"
set ttt_reportdrops "0"
label .packets -textvariable ttt_packets
label .drops -textvariable ttt_drops
label .reportdrops -textvariable ttt_reportdrops

htext .stat -text {\
pcap stat: recv [ %%
label $htext(widget).packets -textvariable ttt_packets
$htext(widget) append $htext(widget).packets \
%%] \
drop [ %%
label $htext(widget).drops -textvariable ttt_drops
$htext(widget) append $htext(widget).drops \
%%]
 ttt report: lost [ %%
label $htext(widget).reportdrops -textvariable ttt_reportdrops
$htext(widget) append $htext(widget).reportdrops \
%%] \
}


# ttt message shown at the bottom of the window
set ttt_message ""
label .bottomlabel -textvariable ttt_message -fg yellow

table .f \
    .graph 0,0  \
    .graph2 1,0  \
    .stat 2,0 -padx 20 \
    .footer 4,0 -padx 20 \
    .bottomlabel 5,0 -padx 30

table configure .f .graph .graph2 .stat \
	.footer .bottomlabel -fill both

table . .f -fill both
wm min . 0 0

#Blt_ZoomStack $graph
#Blt_Crosshairs $graph
#Blt_ActiveLegend $graph
#Blt_ClosestPoint $graph

#Blt_ZoomStack $graph2
#Blt_Crosshairs $graph2
#Blt_ActiveLegend $graph2
#Blt_ClosestPoint $graph2

