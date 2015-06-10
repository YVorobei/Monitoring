#!/bin/bash
rm group_Maxiget.log
rm sourse_site.log

#checklist sites
sites_list=( maxiget.com getportal.net )

for checking_site in ${sites_list[@]}
do

count_grep=0
safebrowsing=http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=$checking_site
siteadvisor=http://www.siteadvisor.com/sites/$checking_site
avgthreatlabs=http://www.avgthreatlabs.com/ww-en/website-safety-reports/domain/$checking_site
sitecheck_sucuri=https://sitecheck.sucuri.net/results/$checking_site
quttera=http://www.quttera.com/detailed_report/$checking_site
	
	for (( count=0; count<5; count++ ))
	do

#----------------*** Check Safebrowsing ***--------------------

		if ((count==0))
		then
		wget -O sourse_site.log $safebrowsing > /dev/null 2>&1
		sleep 1s > /dev/null 2>&1
		grep 'This site is not currently listed as suspicious.*0 page(s) resulted in malicious software being downloaded and installed without user consent' sourse_site.log  > /dev/null 2>&1
	
		if (($? == 0))
			   then
			 echo $checking_site safebrowsing -- OK >> group_Maxiget.log
	   	   else 
			 echo $checking_site safebrowsing -- False >> group_Maxiget.log
		fi
		
#----------------*** Check Siteadvisor ***--------------------

		elif((count==1))
			then
			wget -O sourse_site.log $siteadvisor > /dev/null 2>&1
			sleep 1s > /dev/null 2>&1
			grep 'This link is safe. We tested it and didn'\''t find any significant security issues.\|This link isn'\''t rated. Either we don'\''t have enough information, or we haven'\''t tested 	it yet. Proceed with caution.' sourse_site.log  > /dev/null 2>&1
	
			if (($? == 0))
				   then
				 echo $checking_site siteadvisor -- OK >> group_Maxiget.log
		   	   else 
				 echo $checking_site siteadvisor -- False >> group_Maxiget.log
			fi

#----------------*** Check Avgthreatlabs ***--------------------

		elif((count==2))
			then
			wget -O sourse_site.log --user-agent="Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:35.0) Gecko/20100101 Firefox/35.0" $avgthreatlabs > /dev/null 2>&1
			sleep 1s > /dev/null
			grep '<h2 class="green">Currently Safe</h2>' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=1
						echo $count_grep > /dev/null 2>&1
				fi
			grep 'No active malware was reported recently by users anywhere on this website' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=2
						echo $count_grep > /dev/null 2>&1
				fi
				if (($count_grep == 0))
					then
						echo $checking_site safebrowsing -- OK >> group_Maxiget.log
					else 
						echo $checking_site safebrowsing -- False >> group_Maxiget.log
				fi

#----------------*** Check Sitecheck_sucuri ***--------------------

		elif((count==3))
			then
			wget -O sourse_site.log $sitecheck_sucuri > /dev/null 2>&1
			sleep 1s > /dev/null
			grep 'No Malware Detected by External Scan' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=1
						echo $count_grep > /dev/null 2>&1
				fi
			grep 'Not Currently Blacklisted <small>(10 Blacklists Checked)' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=2
						echo $count_grep > /dev/null 2>&1
				fi
		if (($count_grep == 0))
			then
				echo $checking_site sitecheck_sucuri -- OK >> group_Maxiget.log
			else 
				echo $checking_site sitecheck_sucuri -- False >> group_Maxiget.log
		fi

#----------------*** Check Quttera ***--------------------

		elif((count==4))
			then
			wget -O sourse_site.log $quttera > /dev/null 2>&1
			sleep 1s > /dev/null	
			grep 'PhishTank - domain is Clean.' sourse_site.log > /dev/null 2>&1
			if (($? == 0))
				then			
					echo $count_grep > /dev/null 2>&1
				else 
					count_grep=1
					echo $count_grep > /dev/null 2>&1
			fi
			grep 'Quttera Labs - domain is Clean.' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=2
						echo $count_grep > /dev/null 2>&1
				fi
			grep 'Yandex-SafeBrowsing - domain is Clean' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=3
						echo $count_grep > /dev/null 2>&1
				fi 
			grep 'Google-SafeBrowsing - domain is Clean.' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=4
						echo $count_grep > /dev/null 2>&1
				fi
			grep 'MalwareDomainList - domain is Clean.' sourse_site.log > /dev/null 2>&1
				if (($? == 0))
					then			
						echo $count_grep > /dev/null 2>&1
					else 
						count_grep=5
						echo $count_grep > /dev/null 2>&1
				fi

		if (($count_grep == 0))
			then
				echo $checking_site quttera -- OK >> group_Maxiget.log
			else 
				echo $checking_site quttera -- False >> group_Maxiget.log
		fi

		fi
	done
	echo ---------------------------------------- >> group_Maxiget.log
done
