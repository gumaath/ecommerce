<?php 

namespace Hcode;

class PageAdmin extends Page {
    
    public function __construct($opt = array(), $tpl_dir = "/views/admin/") {
        parent::__construct($opt, $tpl_dir);
    }
}

?>