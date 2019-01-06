#!/usr/bin/env bash
echo "DCTCP"
sudo bash run.sh /mnt/dcint/dctcp
echo "VL2"
sudo bash run.sh /mnt/dcint/vl2
echo "FB_CACHE"
sudo bash run.sh /mnt/dcint/fb_cache
echo "FB_HADOOP"
sudo bash run.sh /mnt/dcint/fb_hadoop
echo "FB_WEB"
sudo bash run.sh /mnt/dcint/fb_web

